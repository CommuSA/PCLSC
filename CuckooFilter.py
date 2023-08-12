import random


class CuckooFilter:
    def __init__(self, size, max_kicks=500):
        self.size = size
        self.max_kicks = max_kicks
        self.table = [None] * size

    def _hash_functions(self, item):
        hash1 = hash(item) % self.size
        hash2 = (hash(item) ^ hash1) % self.size
        return hash1, hash2

    def insert(self, item):
        hash1, hash2 = self._hash_functions(item)
        if self.table[hash1] is None:
            self.table[hash1] = item
            return True
        elif self.table[hash2] is None:
            self.table[hash2] = item
            return True
        else:
            # Kick out existing item
            for _ in range(self.max_kicks):
                random_index = random.choice([hash1, hash2])
                kicked_item = self.table[random_index]
                self.table[random_index] = item
                item = kicked_item
                hash1, hash2 = self._hash_functions(item)
                if self.table[hash1] is None:
                    self.table[hash1] = item
                    return True
                elif self.table[hash2] is None:
                    self.table[hash2] = item
                    return True
            return False

    def contains(self, item):
        hash1, hash2 = self._hash_functions(item)
        return self.table[hash1] == item or self.table[hash2] == item

    def delete(self, item):
        hash1, hash2 = self._hash_functions(item)
        finish = False
        if (self.table[hash1] == item):
            self.table[hash1] == None
            finish = True

        if (self.table[hash2] == item):
            self.table[hash2] == None
            finish = True
            print("2")

        return finish
