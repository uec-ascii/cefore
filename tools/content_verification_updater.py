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


def add_verification_entry(payload: bytes, packet_info: bytes):
    """
    コンテンツ検証エントリをcefnetdに追加する
    
    Args:
        payload: ペイロードのバイナリデータ
        packet_info: パケット情報（name:chunk_num形式）のバイナリデータ
    """
    # payloadのSHA256ハッシュを計算
    hashkey = hashlib.sha256(payload).digest()
    
    # データフォーマット: [hashkey(32bytes)][data_len(4bytes)][data(variable)]
    data_len = len(packet_info)
    message = hashkey + struct.pack('I', data_len) + packet_info
    
    print(f"[INFO] Adding verification entry:")
    print(f"  Hashkey: {hashkey.hex()}")
    print(f"  Packet info: {packet_info}")
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
    
    # 例1: 固定データ（既存のテストデータと同じ）
    print("\n=== Example 1: Fixed test data ===")
    payload1 = b"test_payload_content"
    packet_info1 = b"\x00\x01\x00\x06server\x00\x01\x00\x04file\x00\x04\x00\x04\x00\x00\x00\x00:0"
    add_verification_entry(payload1, packet_info1)
    
    # 例2: 動的生成データ
    print("\n=== Example 2: Dynamic data ===")
    payload2 = b"This is dynamic content for chunk 1"
    # ccn:/example/data:1 のようなパケット情報を構築
    name = b"\x00\x01\x00\x07example\x00\x01\x00\x04data"
    chunk_num = 1
    packet_info2 = name + f":{chunk_num}".encode('ascii')
    add_verification_entry(payload2, packet_info2)
    
    # 例3: ファイルから読み込んだデータ
    print("\n=== Example 3: Data from file ===")
    test_file = "/tmp/test_content.txt"
    if os.path.exists(test_file):
        with open(test_file, 'rb') as f:
            payload3 = f.read()
        packet_info3 = b"\x00\x01\x00\x04file\x00\x01\x00\x07content:0"
        add_verification_entry(payload3, packet_info3)
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
        
        name_str = input("Name (e.g., ccn:/server/file): ")
        if name_str.lower() == 'q':
            break
        
        chunk_num_str = input("Chunk number: ")
        if chunk_num_str.lower() == 'q':
            break
        
        try:
            chunk_num = int(chunk_num_str)
        except ValueError:
            print("[ERROR] Invalid chunk number")
            continue
        
        # 簡易的なname変換（実際のCCN nameフォーマットに変換する場合は要実装）
        # ここでは例として単純な文字列として扱う
        payload = payload_str.encode('utf-8')
        packet_info = f"{name_str}:{chunk_num}".encode('utf-8')
        
        add_verification_entry(payload, packet_info)


if __name__ == "__main__":
    print("Content Verification Entry Updater")
    print("===================================")
    
    if len(sys.argv) > 1 and sys.argv[1] == "-i":
        interactive_mode()
    else:
        example_usage()
    
    print("\n[INFO] Done")
