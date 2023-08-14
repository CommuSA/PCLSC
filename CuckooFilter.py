import random


class CuckooFilter:
    def __init__(self, capacity, bucket_size, fingerprint_size, max_kicks=500):
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.fingerprint_size = fingerprint_size
        self.max_kicks = max_kicks
        self.table = [
            [None] * bucket_size for _ in range(capacity // bucket_size)]

    def _hash_functions(self, item):
        hash1 = hash(item) % self.capacity
        hash2 = (hash(item) ^ hash1) % self.capacity
        return hash1, hash2

    def _get_fingerprint(self, item):
        return hash(item) & ((1 << self.fingerprint_size) - 1)

    def insert(self, item):
        hash1, hash2 = self._hash_functions(item)
        fingerprint = self._get_fingerprint(item)
        for _ in range(self.max_kicks):
            if self._insert_to_bucket(hash1, fingerprint):
                return True
            if self._insert_to_bucket(hash2, fingerprint):
                return True
            random_index = random.choice([hash1, hash2])
            random_bucket = self.table[random_index]
            random_index = random.choice(range(self.bucket_size))
            kicked_fingerprint = random_bucket[random_index]
            random_bucket[random_index] = fingerprint
            fingerprint = kicked_fingerprint
        return False

    def _insert_to_bucket(self, index, fingerprint):
        bucket_index = index % (self.capacity // self.bucket_size)
        bucket = self.table[bucket_index]
        for i in range(self.bucket_size):
            if bucket[i] is None:
                bucket[i] = fingerprint
                return True
        return False

    def contains(self, item):
        hash1, hash2 = self._hash_functions(item)
        fingerprint = self._get_fingerprint(item)
        return self._contains_in_bucket(hash1, fingerprint) or self._contains_in_bucket(hash2, fingerprint)

    def _contains_in_bucket(self, index, fingerprint):
        bucket_index = index % (self.capacity // self.bucket_size)
        bucket = self.table[bucket_index]
        return fingerprint in bucket

    def delete(self, item):
        hash1, hash2 = self._hash_functions(item)
        fingerprint = self._get_fingerprint(item)
        if self._delete_from_bucket(hash1, fingerprint):
            return True
        if self._delete_from_bucket(hash2, fingerprint):
            return True
        return False

    def _delete_from_bucket(self, index, fingerprint):
        bucket_index = index % (self.capacity // self.bucket_size)
        bucket = self.table[bucket_index]
        if fingerprint in bucket:
            bucket.remove(fingerprint)
            return True
        return False
