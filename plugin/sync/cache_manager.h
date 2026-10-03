#pragma once

#ifdef wait
#undef wait
#endif
#ifdef waitid
#undef waitid
#endif
#ifdef waitpid
#undef waitpid
#endif

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>
#include <mutex>

namespace cache {

    inline std::atomic<uint64_t>& GetIdbGeneration() {
        static std::atomic<uint64_t> s_gen{1};
        return s_gen;
    }

    inline uint64_t CurrentGeneration() {
        return GetIdbGeneration().load(std::memory_order_acquire);
    }

    inline uint64_t NextGeneration() {
        return GetIdbGeneration().fetch_add(1, std::memory_order_acq_rel) + 1;
    }

    class CacheManager {
    public:
        using Invalidator = std::function<void()>;

        static CacheManager& Instance() {
            static CacheManager s_inst;
            return s_inst;
        }

        void RegisterByteInvalidator(Invalidator fn) {
            std::lock_guard<std::mutex> lock(mtx_);
            byte_invalidators_.push_back(std::move(fn));
        }

        void RegisterAnalysisInvalidator(Invalidator fn) {
            std::lock_guard<std::mutex> lock(mtx_);
            analysis_invalidators_.push_back(std::move(fn));
        }

        // Call when raw binary bytes or code instructions are patched in IDB
        void InvalidateBytes() {
            NextGeneration();
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto& fn : byte_invalidators_) {
                try { fn(); } catch (...) {}
            }
        }

        // Call when types, symbols, comments, or structure definitions change
        void InvalidateAnalysis() {
            NextGeneration();
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto& fn : analysis_invalidators_) {
                try { fn(); } catch (...) {}
            }
        }

        // Invalidate all caches across the entire plugin (e.g. after python execution or batch patches)
        void InvalidateAll() {
            NextGeneration();
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto& fn : byte_invalidators_) {
                try { fn(); } catch (...) {}
            }
            for (auto& fn : analysis_invalidators_) {
                try { fn(); } catch (...) {}
            }
        }

    private:
        std::mutex mtx_;
        std::vector<Invalidator> byte_invalidators_;
        std::vector<Invalidator> analysis_invalidators_;
    };

    // Global mutation hook convenience helpers
    inline void InvalidateIDBBytes() {
        CacheManager::Instance().InvalidateBytes();
    }

    inline void InvalidateIDBAnalysis() {
        CacheManager::Instance().InvalidateAnalysis();
    }

    inline void InvalidateIDBDependentCaches() {
        CacheManager::Instance().InvalidateAll();
    }
}
