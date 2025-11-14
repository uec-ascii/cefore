#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Content Verification Entry Updater for cefnetd

このスクリプトは、名前付きパイプ（FIFO）を通じて
cefnetdのコンテンツ検証用HashMapにエントリを追加し、
検証失敗通知を受け取ってFIBエントリを削除する。

使用例:
    python3 content_verification_updater.py
    python3 content_verification_updater.py --daemon  # デーモンモード
"""

import struct
import hashlib
import os
import sys
import time
import subprocess
import threading
import signal

# FIFOのパス
FIFO_PATH = "/tmp/cefnetd_verify.fifo"
NOTIFY_FIFO_PATH = "/tmp/cefnetd_verify_notify.fifo"

# 登録されたコンテンツ名のセット（検証失敗時のFIB削除判定用）
registered_contents = set()
running = True


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
        # 登録成功したらセットに追加
        registered_contents.add(name.decode('utf-8', errors='ignore'))
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


def handle_verification_failure(name: str, host: str, protocol: str):
    """
    検証失敗を処理してFIBからエントリを削除する
    
    Args:
        name: コンテンツ名
        host: ホストアドレス
        protocol: プロトコル（tcp/udp）
    """
    print(f"\n[WARN] Verification failed:")
    print(f"  Name: {name}")
    print(f"  Host: {host}")
    print(f"  Protocol: {protocol}")
    
    # コンテンツが登録されているかチェック
    # プレフィックスマッチング（Chunk情報を除いたベース名で判定）
    base_name = name.rsplit('/Chunk=', 1)[0] if '/Chunk=' in name else name
    # 0x形式のチャンク指定も除去
    if '/0x' in base_name:
        base_name = base_name.rsplit('/0x', 1)[0]
    
    is_registered = any(
        registered.startswith(base_name) or base_name.startswith(registered.rsplit('/Chunk=', 1)[0])
        for registered in registered_contents
    )
    
    if not is_registered:
        print(f"[INFO] Content not registered, skipping FIB deletion")
        return
    
    print(f"[ACTION] Registered content failed verification, removing FIB entry...")
    
    # プレフィックスを後ろから削っていって全てのパターンで削除を試行
    prefixes_to_try = []
    current = name
    
    # 完全なnameから始める
    prefixes_to_try.append(current)
    
    # 後ろから'/'で区切りながら削っていく
    while '/' in current:
        # 最後の'/'の位置を見つける
        last_slash = current.rfind('/')
        
        # '/'を含むバージョンと含まないバージョンを追加
        current_with_slash = current[:last_slash + 1]
        current_without_slash = current[:last_slash]
        
        if current_with_slash not in prefixes_to_try:
            prefixes_to_try.append(current_with_slash)
        if current_without_slash and current_without_slash not in prefixes_to_try:
            prefixes_to_try.append(current_without_slash)
        
        current = current_without_slash
    
    print(f"[INFO] Trying to remove FIB entries for {len(prefixes_to_try)} prefix patterns")
    
    success_count = 0
    for prefix in prefixes_to_try:
        if not prefix:  # 空文字列はスキップ
            continue
            
        try:
            cmd = ["cefroute", "del", prefix, protocol, host]
            
            print(f"[CMD] Trying: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                print(f"[OK] Successfully removed FIB entry for prefix: {prefix}")
                success_count += 1
            else:
                # エラーでも続行（他のプレフィックスを試す）
                print(f"[DEBUG] Failed for prefix '{prefix}': {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"[ERROR] cefroute command timed out for prefix: {prefix}")
        except FileNotFoundError:
            print(f"[ERROR] cefroute command not found")
            break  # コマンドが見つからない場合は以降も失敗するので中断
        except Exception as e:
            print(f"[ERROR] Failed to execute cefroute for prefix '{prefix}': {e}")
    
    if success_count > 0:
        print(f"[OK] Successfully removed {success_count} FIB entry(ies)")
        # 登録から削除
        to_remove = [c for c in registered_contents if c.startswith(base_name)]
        for c in to_remove:
            registered_contents.discard(c)
    else:
        print(f"[WARN] No FIB entries were removed")


def notification_listener():
    """
    検証失敗通知をリッスンするスレッド
    """
    global running
    
    print(f"[INFO] Starting notification listener...")
    
    # 通知用FIFOが作成されるまで待機
    while running and not os.path.exists(NOTIFY_FIFO_PATH):
        time.sleep(0.5)
    
    if not running:
        return
    
    print(f"[OK] Notification FIFO found: {NOTIFY_FIFO_PATH}")
    
    try:
        # 読み取り専用で開く
        with open(NOTIFY_FIFO_PATH, 'rb') as fifo:
            print(f"[INFO] Listening for verification failure notifications...")
            
            while running:
                try:
                    # name_len を読み取り
                    data = fifo.read(2)
                    if len(data) != 2:
                        if not running:
                            break
                        time.sleep(0.1)
                        continue
                    
                    name_len = struct.unpack('!H', data)[0]
                    
                    # name を読み取り
                    name_data = fifo.read(name_len)
                    if len(name_data) != name_len:
                        print(f"[WARN] Incomplete name data")
                        continue
                    name = name_data.decode('utf-8', errors='ignore')
                    
                    # host_len を読み取り
                    data = fifo.read(2)
                    if len(data) != 2:
                        continue
                    host_len = struct.unpack('!H', data)[0]
                    
                    # host を読み取り
                    host_data = fifo.read(host_len)
                    if len(host_data) != host_len:
                        print(f"[WARN] Incomplete host data")
                        continue
                    host = host_data.decode('utf-8', errors='ignore')
                    
                    # protocol_len を読み取り
                    data = fifo.read(2)
                    if len(data) != 2:
                        continue
                    protocol_len = struct.unpack('!H', data)[0]
                    
                    # protocol を読み取り
                    protocol_data = fifo.read(protocol_len)
                    if len(protocol_data) != protocol_len:
                        print(f"[WARN] Incomplete protocol data")
                        continue
                    protocol = protocol_data.decode('utf-8', errors='ignore')
                    
                    # 検証失敗を処理
                    handle_verification_failure(name, host, protocol)
                    
                except Exception as e:
                    if running:
                        print(f"[ERROR] Error reading notification: {e}")
                    break
    except Exception as e:
        if running:
            print(f"[ERROR] Failed to open notification FIFO: {e}")


def signal_handler(sig, frame):
    """シグナルハンドラー"""
    global running
    print("\n[INFO] Shutting down...")
    running = False
    sys.exit(0)


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
    
    # シグナルハンドラーを設定
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        # デーモンモード：通知リスナーを起動
        print("[INFO] Running in daemon mode")
        notification_listener()
        # リスナーが終了するまで待機
        while running:
            time.sleep(1)
    elif len(sys.argv) > 1 and sys.argv[1] == "-i":
        # 対話モード：通知リスナーをバックグラウンドで起動
        listener_thread = threading.Thread(target=notification_listener, daemon=True)
        listener_thread.start()
        interactive_mode()
    else:
        # 例示モード：通知リスナーをバックグラウンドで起動
        listener_thread = threading.Thread(target=notification_listener, daemon=True)
        listener_thread.start()
        example_usage()
    
    print("\n[INFO] Done")
