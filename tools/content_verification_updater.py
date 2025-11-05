#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Content Verification Entry Updater for cefnetd

このスクリプトは、名前付きパイプ（FIFO）を通じて
cefnetdのコンテンツ検証用HashMapにエントリを追加する。

使用例:
    python3 content_verification_updater.py
"""

import struct
import hashlib
import os
import sys
import time

# FIFOのパス
FIFO_PATH = "/tmp/cefnetd_verify.fifo"


def add_verification_entry(payload: bytes, name: bytes):
    """
    コンテンツ検証エントリをcefnetdに追加する
    
    Args:
        payload: ペイロードのバイナリデータ
        name: コンテンツ名（nameにchunk番号が含まれている前提）
    """
    # payloadのSHA256ハッシュを計算
    hashkey = hashlib.sha256(payload).digest()
    
    # データフォーマット: [hashkey(32bytes)][data_len(4bytes)][data(variable)]
    data_len = len(name)
    message = hashkey + struct.pack('I', data_len) + name
    
    print(f"[INFO] Adding verification entry:")
    print(f"  Hashkey: {hashkey.hex()}")
    print(f"  Name: {name}")
    print(f"  Data length: {data_len}")
    
    # FIFOに書き込む
    try:
        with open(FIFO_PATH, 'wb') as fifo:
            fifo.write(message)
        print(f"[OK] Successfully added entry to cefnetd")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write to FIFO: {e}")
        return False


def wait_for_fifo():
    """FIFOが作成されるまで待機"""
    print(f"[INFO] Waiting for FIFO: {FIFO_PATH}")
    while not os.path.exists(FIFO_PATH):
        time.sleep(0.5)
    print(f"[OK] FIFO found")


def example_usage():
    """使用例"""
    # FIFOの存在を確認
    wait_for_fifo()
    
    # 例1: 固定データ（ccn:/server/file/Chunk=0 形式）
    print("\n=== Example 1: Fixed test data ===")
    payload1 = b"test_payload_content"
    name1 = b"ccn:/server/file/Chunk=0"
    add_verification_entry(payload1, name1)
    
    # 例2: 動的生成データ（ccn:/example/data/Chunk=1 形式）
    print("\n=== Example 2: Dynamic data ===")
    payload2 = b"This is dynamic content for chunk 1"
    name2 = b"ccn:/example/data/Chunk=1"
    add_verification_entry(payload2, name2)
    
    # 例3: ファイルから読み込んだデータ
    print("\n=== Example 3: Data from file ===")
    test_file = "/tmp/test_content.txt"
    if os.path.exists(test_file):
        with open(test_file, 'rb') as f:
            payload3 = f.read()
        name3 = b"ccn:/file/content/Chunk=0"
        add_verification_entry(payload3, name3)
    else:
        print(f"[SKIP] Test file not found: {test_file}")


def interactive_mode():
    """対話モード"""
    print("\n=== Interactive Mode ===")
    print("Enter 'q' to quit")
    
    wait_for_fifo()
    
    while True:
        print("\n--- New Entry ---")
        payload_str = input("Payload (text): ")
        if payload_str.lower() == 'q':
            break
        
        name_str = input("Name (e.g., ccn:/server/file/Chunk=0): ")
        if name_str.lower() == 'q':
            break
        
        payload = payload_str.encode('utf-8')
        name = name_str.encode('utf-8')
        
        add_verification_entry(payload, name)


if __name__ == "__main__":
    print("Content Verification Entry Updater")
    print("===================================")
    
    if len(sys.argv) > 1 and sys.argv[1] == "-i":
        interactive_mode()
    else:
        example_usage()
    
    print("\n[INFO] Done")
