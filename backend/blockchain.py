# backend/blockchain.py
import hashlib
import time
import threading

class Block:
    """A single cryptographically linked record in the tactical RAM ledger."""
    def __init__(self, index, agent, action, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.agent = agent
        self.action = action
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Computes a SHA-256 digest of the block's contents."""
        block_data = f"{self.index}{self.timestamp}{self.agent}{self.action}{self.previous_hash}"
        return hashlib.sha256(block_data.encode('utf-8')).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": time.strftime('%H:%M:%S', time.localtime(self.timestamp)),
            "agent": self.agent,
            "action": self.action,
            "hash": self.hash,
            "previous_hash": self.previous_hash
        }


class TacticalLedger:
    """In-memory Zero-Footprint Blockchain with active tamper detection."""
    def __init__(self):
        self.chain = []
        self.lock = threading.Lock()
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "SYSTEM", "TERMINAL BOOT - ZERO FOOTPRINT PROTOCOL ACTIVE", "0" * 64)
        self.chain.append(genesis_block)

    def get_latest_block(self):
        with self.lock:
            return self.chain[-1]

    def add_record(self, agent, action):
        with self.lock:
            previous_block = self.chain[-1]
            new_block = Block(len(self.chain), agent, action, previous_block.hash)
            self.chain.append(new_block)
            return new_block

    def verify_integrity(self):
        """
        Scans the RAM ledger to verify no unauthorized process has modified historical blocks.
        Returns (is_valid: bool, error_message: str).
        """
        with self.lock:
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]

                if current_block.hash != current_block.calculate_hash():
                    return False, f"BLOCK #{current_block.index} HASH MISMATCH (DATA ALTERED IN RAM)"

                if current_block.previous_hash != previous_block.hash:
                    return False, f"CHAIN BROKEN BETWEEN BLOCK #{previous_block.index} AND #{current_block.index}"

            return True, "INTEGRITY VERIFIED"

    def simulate_memory_tamper(self):
        """Viva Demo Helper: Corrupts the latest block in RAM to demonstrate watchdog detection."""
        with self.lock:
            if len(self.chain) > 1:
                self.chain[-1].action = "TAMPERED_BY_ROGUE_PROCESS"
                return True
            return False

    def purge_ledger(self):
        with self.lock:
            self.chain = []
            self.create_genesis_block()
            print("[!] TACTICAL LEDGER PURGED.")
            return self.chain[0]