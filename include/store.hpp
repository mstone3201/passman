#pragma once

#include <unordered_map>
#include <string>

namespace passman {
    template <class T> class store {
    public:
        using index_type = std::uint32_t;
        using const_iterator =
            std::unordered_map<index_type, T>::const_iterator;

        store() : insert_index(0) {}
        store(const store&) = delete;

        store& operator=(const store&) = delete;

        const_iterator begin() const {
            return cbegin();
        }

        const_iterator cbegin() const {
            return map.cbegin();
        }

        const_iterator end() const {
            return cend();
        }

        const_iterator cend() const {
            return map.cend();
        }

        index_type insert(T&& data) {
            if(map.size() >= std::numeric_limits<index_type>::max())
                throw new std::exception("store full");

            // Find the next free index
            while(map.contains(insert_index))
                // Wraps around
                ++insert_index;

            map.emplace(insert_index, std::move(data));
            
            // Increment insert_index to prepare for next insert
            return insert_index++;
        }

        bool erase(index_type index) {
            return map.erase(index);
        }

        T& operator[](index_type index) {
            return map[index];
        }
    private:
        std::unordered_map<index_type, T> map;
        index_type insert_index;
    };
}
