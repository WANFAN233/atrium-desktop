#include "log.h"

#include "settings.h"

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <share.h>
#include <string>
#include <thread>
#include <vector>

namespace atrium {

namespace {

std::wstring LogPath()
{
    std::wstring dir = DataDirectory() + L"\\logs";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\core.log";
}

// Trivially-destructible flush state stays valid even if static destruction outruns a stalled FlushLog call.
struct FlushState {
    std::atomic<HANDLE> wakeEvent{nullptr};
    std::atomic<DWORD> writerThreadId{0};
    std::atomic<DWORD> addOwnerThreadId{0};
    std::atomic<uint64_t> queuedSeq{0};
    std::atomic<uint64_t> processedSeq{0};
    std::atomic<uint64_t> flushedOkSeq{0};
    std::atomic<bool> exited{false};
};

std::atomic<bool> g_logStarted{false};
std::atomic<bool> g_logStopped{false};
std::atomic<uint32_t> g_activeFlushes{0};
FlushState g_flushState{};

struct ScopedAddOwner {
    ScopedAddOwner() { g_flushState.addOwnerThreadId.store(GetCurrentThreadId(), std::memory_order_relaxed); }
    ~ScopedAddOwner() { g_flushState.addOwnerThreadId.store(0, std::memory_order_relaxed); }

    ScopedAddOwner(const ScopedAddOwner&) = delete;
    ScopedAddOwner& operator=(const ScopedAddOwner&) = delete;
};

struct ScopedActiveFlush {
    ScopedActiveFlush() { g_activeFlushes.fetch_add(1, std::memory_order_seq_cst); }
    ~ScopedActiveFlush() { g_activeFlushes.fetch_sub(1, std::memory_order_seq_cst); }

    ScopedActiveFlush(const ScopedActiveFlush&) = delete;
    ScopedActiveFlush& operator=(const ScopedActiveFlush&) = delete;
};

void SignalWakeEvent()
{
    if (HANDLE wake = g_flushState.wakeEvent.load(std::memory_order_acquire))
        SetEvent(wake);
}

// Lock-free wait so a crash handler never blocks on a held mutex or an unbounded condition-variable re-lock.
bool FlushLogImpl(unsigned long timeoutMs)
{
    const DWORD self = GetCurrentThreadId();
    if (self == g_flushState.writerThreadId.load(std::memory_order_relaxed) || self == g_flushState.addOwnerThreadId.load(std::memory_order_relaxed)) {
        return false;
    }
    const uint64_t target = g_flushState.queuedSeq.load(std::memory_order_acquire);
    if (g_flushState.processedSeq.load(std::memory_order_acquire) >= target)
        return g_flushState.flushedOkSeq.load(std::memory_order_acquire) >= target;
    const HANDLE wake = g_flushState.wakeEvent.load(std::memory_order_acquire);
    if (!wake)
        return false;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (g_flushState.processedSeq.load(std::memory_order_acquire) < target && !g_flushState.exited.load(std::memory_order_acquire)) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            break;
        const ULONGLONG remaining = deadline - now;
        const DWORD slice = static_cast<DWORD>(remaining < 25 ? remaining : 25);
        WaitForSingleObject(wake, slice);
    }
    return g_flushState.flushedOkSeq.load(std::memory_order_acquire) >= target;
}

bool WriteLogBatch(FILE*& file, const std::wstring& path, const std::wstring& backup, unsigned long long& written, unsigned long long maxBytes,
                   const std::vector<std::wstring>& lines)
{
    if (!file)
        return false;
    bool ok = true;
    for (const std::wstring& l : lines) {
        if (fputws(l.c_str(), file) == WEOF) {
            ok = false;
            continue;
        }
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, l.data(), static_cast<int>(l.size()), nullptr, 0, nullptr, nullptr);
        if (bytes > 0)
            written += static_cast<unsigned>(bytes);
        if (written > maxBytes) {
            if (fflush(file) != 0)
                ok = false;
            fclose(file);
            MoveFileExW(path.c_str(), backup.c_str(), MOVEFILE_REPLACE_EXISTING);
            file = _wfsopen(path.c_str(), L"a, ccs=UTF-8", _SH_DENYNO);
            written = 0;
            if (!file)
                return false;
        }
    }
    if (fflush(file) != 0)
        ok = false;
    return ok;
}

// Lines are written by a thread of their own into a file kept open: opening
// and closing it for every line (a virus scan each time) took milliseconds,
// under a lock every thread shared - animations stalled on their own log
// lines. A file over 8 MB is moved to core.1.log at start and on overflow.
class Writer {
public:
    static Writer& Get()
    {
        static Writer w;
        return w;
    }

    void Add(std::wstring line)
    {
        if (g_logStopped.load(std::memory_order_acquire) || !EnsureStarted())
            return;
        constexpr size_t kMaxQueue = 4096;
        bool active = false;
        {
            std::lock_guard g(mutex_);
            ScopedAddOwner addOwner;
            if (!stop_ && !g_logStopped.load(std::memory_order_relaxed)) {
                if (queue_.size() >= kMaxQueue)
                    ++dropped_;
                else
                    queue_.push_back(std::move(line));
                g_flushState.queuedSeq.fetch_add(1, std::memory_order_release);
                active = true;
            }
        }
        if (active)
            cv_.notify_one();
    }

    void Shutdown()
    {
        std::lock_guard lifecycleLock(lifecycleMutex_);
        g_logStopped.store(true, std::memory_order_seq_cst);
        if (!started_)
            return;
        {
            std::lock_guard g(mutex_);
            stop_ = true;
        }
        cv_.notify_one();
        if (thread_.joinable())
            thread_.join();
        started_ = false;
    }

    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

private:
    Writer() = default;
    ~Writer()
    {
        Shutdown();
        if (g_activeFlushes.load(std::memory_order_seq_cst) > 0) {
            HANDLE drainEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            const ULONGLONG deadline = GetTickCount64() + 500;
            while (g_activeFlushes.load(std::memory_order_seq_cst) > 0 && GetTickCount64() < deadline && drainEvent)
                WaitForSingleObject(drainEvent, 10);
            if (drainEvent)
                CloseHandle(drainEvent);
        }
        if (g_activeFlushes.load(std::memory_order_seq_cst) == 0) {
            if (HANDLE wake = g_flushState.wakeEvent.exchange(nullptr, std::memory_order_acq_rel))
                CloseHandle(wake);
        }
    }

    bool EnsureStarted()
    {
        if (g_logStarted.load(std::memory_order_acquire))
            return !g_logStopped.load(std::memory_order_acquire);
        std::lock_guard lifecycleLock(lifecycleMutex_);
        if (g_logStopped.load(std::memory_order_acquire))
            return false;
        if (!started_) {
            if (!g_flushState.wakeEvent.load(std::memory_order_acquire))
                g_flushState.wakeEvent.store(CreateEventW(nullptr, FALSE, FALSE, nullptr), std::memory_order_release);
            g_flushState.exited.store(false, std::memory_order_release);
            stop_ = false;
            thread_ = std::thread([this] { Run(); });
            started_ = true;
            g_logStarted.store(true, std::memory_order_release);
        }
        return true;
    }

    void Run()
    {
        g_flushState.writerThreadId.store(GetCurrentThreadId(), std::memory_order_relaxed);
        SetThreadDescription(GetCurrentThread(), L"Atrium log");
        constexpr unsigned long long kMaxBytes = 8ULL << 20;
        const std::wstring path = LogPath();
        const std::wstring backup = path.substr(0, path.size() - 4) + L".1.log";
        unsigned long long written = 0;
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) {
            const unsigned long long size = (static_cast<unsigned long long>(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
            if (size > kMaxBytes)
                MoveFileExW(path.c_str(), backup.c_str(), MOVEFILE_REPLACE_EXISTING);
            else
                written = size;
        }
        FILE* f = _wfsopen(path.c_str(), L"a, ccs=UTF-8", _SH_DENYNO); // others may read it meanwhile
        std::vector<std::wstring> lines;
        bool anyBatchFailed = false;
        for (;;) {
            size_t dropped = 0;
            uint64_t batchSeq = 0;
            {
                std::unique_lock g(mutex_);
                cv_.wait(g, [&] { return stop_ || !queue_.empty() || dropped_ > 0; });
                lines.swap(queue_);
                dropped = dropped_;
                dropped_ = 0;
                batchSeq = g_flushState.queuedSeq.load(std::memory_order_acquire);
                if (lines.empty() && dropped == 0 && stop_)
                    break;
            }
            if (dropped > 0) {
                SYSTEMTIME t;
                GetLocalTime(&t);
                wchar_t summary[128];
                swprintf_s(summary, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%lu] log: dropped %zu lines (queue full)\n", t.wYear, t.wMonth, t.wDay, t.wHour,
                           t.wMinute, t.wSecond, t.wMilliseconds, GetCurrentThreadId(), dropped);
                lines.emplace_back(summary);
            }
            const bool batchOk = WriteLogBatch(f, path, backup, written, kMaxBytes, lines);
            lines.clear();
            if (!batchOk)
                anyBatchFailed = true;
            else if (!anyBatchFailed)
                g_flushState.flushedOkSeq.store(batchSeq, std::memory_order_release);
            g_flushState.processedSeq.store(batchSeq, std::memory_order_release);
            SignalWakeEvent();
        }
        if (f)
            fclose(f);
        g_flushState.exited.store(true, std::memory_order_release);
        SignalWakeEvent();
    }

    std::mutex lifecycleMutex_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::wstring> queue_;
    size_t dropped_ = 0;
    bool started_ = false;
    bool stop_ = false;
    std::thread thread_;
};

} // namespace

void Log(const wchar_t* format, ...)
{
    wchar_t text[1024];
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(text, _TRUNCATE, format, args);
    va_end(args);

    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t line[1200];
    swprintf_s(line, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [%lu] %s\n", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
               GetCurrentThreadId(), text);
    OutputDebugStringW(line);
    if (g_logStopped.load(std::memory_order_acquire))
        return;
    Writer::Get().Add(line);
}

void WriteDebugMessage(const wchar_t* message) { OutputDebugStringW(message); }

bool FlushLog(unsigned long timeoutMs)
{
    ScopedActiveFlush activeFlush;
    if (g_logStopped.load(std::memory_order_seq_cst))
        return false;
    if (!g_logStarted.load(std::memory_order_acquire))
        return true;
    return FlushLogImpl(timeoutMs);
}

void ShutdownLog() { Writer::Get().Shutdown(); }

} // namespace atrium
