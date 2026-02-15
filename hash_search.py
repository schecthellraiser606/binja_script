import sqlite3
import struct
import os
import re
import ctypes
from binaryninja import (
    BinaryView, 
    interaction, 
    enums, 
    Type, 
    StructureBuilder, 
    log_info, 
    log_warn, 
    log_debug,
    BackgroundTaskThread
)

# --- SQL Queries ---
SQL_LOOKUP_HASH_TYPE_VALUE = """
select h.hash_val, h.symbol_name, l.lib_name, t.hash_name, t.hash_size
from symbol_hashes h, source_libs l, hash_types t
where h.hash_val=? and h.lib_key=l.lib_key and h.hash_type=t.hash_type and h.hash_type=?;
"""
SQL_GET_ALL_HASH_TYPES = "select hash_type, hash_size, hash_name, hash_code from hash_types;"

class SymbolHash:
    def __init__(self, hash_val, symbol_name, lib_name, hash_name, hash_size):
        self.hash_val = hash_val
        self.symbol_name = symbol_name
        self.lib_name = lib_name
        self.hash_name = hash_name
        self.hash_size = hash_size
    def __str__(self):
        return f"{self.hash_name}:0x{self.hash_val & 0xFFFFFFFF:08x} {self.lib_name}!{self.symbol_name}"

class HashType:
    def __init__(self, hash_type, hash_size, hash_name, hash_code):
        self.hash_type = hash_type
        self.hash_size = hash_size
        self.hash_name = hash_name
        self.hash_code = hash_code

class DbStore:
    def __init__(self, db_path):
        self.db_path = db_path
        # check_same_thread=False を指定することで、別スレッドからのアクセスを許可します
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._cache = {}

    def get_all_hash_types(self):
        cur = self.conn.execute(SQL_GET_ALL_HASH_TYPES)
        return [HashType(*row) for row in cur]

    def get_symbol_by_type_hash(self, hash_type, hash_val):
        key = (hash_type, hash_val)
        if key in self._cache: return self._cache[key]
        cur = self.conn.execute(SQL_LOOKUP_HASH_TYPE_VALUE, (ctypes.c_int64(hash_val).value, hash_type))
        res = [SymbolHash(*row) for row in cur]
        self._cache[key] = res
        return res

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

class ShellcodeSearchTask(BackgroundTaskThread):
    def __init__(self, bv, dbstore, params):
        super().__init__("Searching shellcode hashes...", True)
        self.bv = bv
        self.dbstore = dbstore
        self.params = params
        self.hits = []
        self.ptr_size = bv.address_size

    def run(self):
        try:
            if self.params['use_push']:
                self.progress = "Searching Instructions (IL)..."
                self.search_instructions()
            
            if self.params['use_dword']:
                self.progress = "Searching Data Arrays..."
                self.search_data()
                
            if self.params['create_struct']:
                self.progress = "Creating Structures..."
                self.create_structures()
        except Exception as e:
            log_warn(f"Error during search: {e}")
        finally:
            self.dbstore.close()
            log_info("Search Complete.")

    def add_hit(self, addr, sym):
        self.hits.append((addr, sym))
        comment = f"{sym.lib_name}!{sym.symbol_name}"
        # コメント付与はメインスレッドで実行される必要がある場合があるため念のためログ
        self.bv.set_comment_at(addr, comment)

    def search_instructions(self):
        for func in self.bv.functions:
            if self.cancelled: return
            for block in func.low_level_il:
                for instr in block:
                    constants = []
                    def find_constants(expr):
                        if hasattr(expr, 'constant'):
                            constants.append((expr.address, expr.constant))
                        if hasattr(expr, 'operands'):
                            for op in expr.operands:
                                if isinstance(op, list):
                                    for sub_op in op: find_constants(sub_op)
                                else: find_constants(op)
                    
                    find_constants(instr)
                    for addr, val in constants:
                        search_val = (val ^ self.params['xor_seed']) if self.params['use_xor'] else val
                        search_val &= 0xFFFFFFFF
                        for h_type in self.params['hash_types']:
                            hits = self.dbstore.get_symbol_by_type_hash(h_type.hash_type, search_val)
                            for sym in hits:
                                self.add_hit(addr, sym)

    def search_data(self):
        for seg in self.bv.segments:
            if self.cancelled: return
            # データ領域のみを対象にする (簡略化のため全セグメントをスキャン)
            data = self.bv.read(seg.start, seg.end - seg.start)
            if not data: continue
            
            for i in range(0, len(data) - 4, 4):
                if i % 1000 == 0 and self.cancelled: return
                val = struct.unpack_from("<I", data, i)[0]
                addr = seg.start + i
                search_val = (val ^ self.params['xor_seed']) if self.params['use_xor'] else val
                for h_type in self.params['hash_types']:
                    if h_type.hash_size == 32:
                        hits = self.dbstore.get_symbol_by_type_hash(h_type.hash_type, search_val)
                        for sym in hits:
                            self.add_hit(addr, sym)

    def create_structures(self):
        if not self.hits: return
        sorted_hits = sorted(self.hits, key=lambda x: x[0])
        i = 0
        struct_idx = 0
        while i < len(sorted_hits):
            current_group = [sorted_hits[i]]
            while (i + 1 < len(sorted_hits) and 
                   sorted_hits[i+1][0] == sorted_hits[i][0] + self.ptr_size):
                current_group.append(sorted_hits[i+1])
                i += 1
            
            if len(current_group) > 1:
                sb = StructureBuilder()
                used_names = {}
                for addr, sym in current_group:
                    name = re.sub(r'[^a-zA-Z0-9_]', '_', sym.symbol_name)
                    used_names[name] = used_names.get(name, 0) + 1
                    if used_names[name] > 1: name += f"_{used_names[name]}"
                    sb.append(Type.int(self.ptr_size, False), name)
                
                struct_name = f"shellcode_funcs_{struct_idx}"
                self.bv.define_user_type(struct_name, Type.structure_type(sb))
                self.bv.define_user_data_var(current_group[0][0], Type.named_type_from_registered_type(self.bv, struct_name))
                struct_idx += 1
            i += 1

def run_plugin(bv):
    db_path = interaction.get_open_filename_input("Select sc_hashes.db", "*.db")
    if not db_path: return
    db_path = db_path.decode('utf-8') if isinstance(db_path, bytes) else db_path
    
    if not os.path.exists(db_path):
        return

    # メインスレッドで型情報をロードするため一時的に接続
    temp_db = DbStore(db_path)
    hash_types = temp_db.get_all_hash_types()
    temp_db.close()

    choices = ["No", "Yes"]
    use_push = interaction.ChoiceField("Search Instructions (IL)", choices)
    use_dword = interaction.ChoiceField("Search Data Arrays", choices)
    use_struct = interaction.ChoiceField("Create Structures", choices)
    use_xor = interaction.ChoiceField("XOR seed hash values", choices)
    xor_seed = interaction.IntegerField("XOR Seed (e.g. 0x1234)")

    if not interaction.get_form_input([
        "--- Search Options (0=No, 1=Yes) ---", 
        use_push, use_dword, use_struct, 
        "--- XOR Config ---",
        use_xor, xor_seed
    ], "Shellcode Hash Search"):
        return

    params = {
        'hash_types': hash_types,
        'use_push': use_push.result == 1,
        'use_dword': use_dword.result == 1,
        'use_xor': use_xor.result == 1,
        'xor_seed': xor_seed.result if xor_seed.result is not None else 0,
        'create_struct': use_struct.result == 1
    }

    # タスク内で個別にDBを開くように設定
    db = DbStore(db_path)
    task = ShellcodeSearchTask(bv, db, params)
    task.start()

if __name__ == "__main__":
    if 'bv' in globals():
        run_plugin(bv)