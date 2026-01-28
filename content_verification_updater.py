#!/usr/bin/env python3
"""
EthereumのブロックをポーリングしてBlockchainの更新通知を受信し続けるスクリプト

動作:
1. Ethereumのブロックを定期的にポーリング
2. 更新があった際、キーとバリューをプリント
3. コンテンツ検証エントリをcefnetdに追加
4. 検証失敗通知を受け取ってFIBエントリを削除
"""

import sys
import json
import time
import struct
import os
import threading
import subprocess
from datetime import datetime
from web3 import Web3

# HTTP接続設定（Web3.py v7ではHTTPポーリングを推奨）
HTTP_URL = "http://172.20.0.10:8545"

# ポーリング間隔（秒）
POLL_INTERVAL = 2

# FIFOのパス
FIFO_PATH = "/tmp/cefnetd_verify.fifo"
NOTIFY_FIFO_PATH = "/tmp/cefnetd_verify_notify.fifo"

# ログファイルのパス
LOG_FILE_PATH = "/tmp/get_update.log"

# 既知のデータを保持（差分検知用）
known_data = {}
last_block_number = 0

# 登録されたコンテンツ名のセット（検証失敗時のFIB削除判定用）
registered_contents = set()
running = True

# 検証用FIFOのファイルハンドル（プログラム起動時に開いて使い回す）
verify_fifo = None

def load_contract_info():
    """デプロイ済みコントラクト情報を読み込み（リトライあり）"""
    # 共有ボリュームから読み込み
    contract_paths = [
        '/app/deployed-contract/deployed-contract.json',  # 共有ボリューム
        '/app/deployed-contract.json',  # フォールバック
    ]
    
    write_log("コントラクト情報の読み込みを開始", also_print=True)
    
    # 最大60秒（30回 × 2秒）待つ
    max_retries = 30
    retry_interval = 2
    
    for attempt in range(max_retries):
        for contract_path in contract_paths:
            try:
                with open(contract_path, 'r') as f:
                    write_log(f"✓ コントラクト情報を読み込みました: {contract_path}", also_print=True)
                    return json.load(f)
            except FileNotFoundError:
                continue
        
        # すべてのパスで見つからなかった場合
        if attempt < max_retries - 1:
            write_log(f"コントラクト情報を待機中... ({attempt + 1}/{max_retries})", also_print=True)
            time.sleep(retry_interval)
        else:
            # 最後の試行でも見つからなかった場合
            write_log("エラー: deployed-contract.json が見つかりません", also_print=True)
            write_log("以下のパスを確認しました:", also_print=True)
            for p in contract_paths:
                write_log(f"  - {p}", also_print=True)
    sys.exit(1)

def add_verification_entry_to_fifo(hashkey_hex: str, ccnx_uri: str):
    """
    コンテンツ検証エントリをcefnetdに追加する
    
    Args:
        hashkey_hex: SHA256ハッシュ（16進数文字列、0xプレフィックス付き）
        ccnx_uri: ccnx URIとチャンク番号（例: ccnx:/server/file/0x0004=0x00000000）
    """
    global verify_fifo
    
    try:
        # ハッシュキーをバイナリに変換
        if hashkey_hex.startswith('0x'):
            hashkey_hex = hashkey_hex[2:]
        hashkey = bytes.fromhex(hashkey_hex)
        
        # packet_info（ccnx URI）をバイト列に変換
        packet_info = ccnx_uri.encode('utf-8')
        
        # データフォーマット: [hashkey(32bytes)][data_len(4bytes)][data(variable)]
        data_len = len(packet_info)
        message = hashkey + struct.pack('I', data_len) + packet_info
        
        # FIFOに書き込む（開きっぱなしのハンドルを使用）
        if verify_fifo is not None:
            verify_fifo.write(message)
            verify_fifo.flush()  # 即座に送信
            # 登録成功したらセットに追加
            registered_contents.add(ccnx_uri)
            print(f"  ✓ cefnetdに登録: {ccnx_uri}")
            return True
        else:
            print(f"  ✗ FIFOが開かれていません", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"  ✗ FIFO書き込みエラー: {str(e)}", file=sys.stderr)
        return False


def write_log(message: str, also_print: bool = True):
    """
    ログファイルとコンソールに出力
    
    Args:
        message: ログメッセージ
        also_print: コンソールにも出力するか
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {message}\n"
    
    try:
        with open(LOG_FILE_PATH, 'a') as f:
            f.write(log_line)
    except Exception as e:
        print(f"ログ書き込みエラー: {e}", file=sys.stderr)
    
    if also_print:
        print(message)


def handle_verification_failure(name: str, host: str, protocol: str):
    """
    検証失敗を処理してFIBからエントリを削除する
    
    Args:
        name: コンテンツ名
        host: ホストアドレス
        protocol: プロトコル（tcp/udp）
    """
    write_log("\n[検証失敗]", also_print=True)
    write_log(f"  Name: {name}", also_print=True)
    write_log(f"  Host: {host}", also_print=True)
    write_log(f"  Protocol: {protocol}", also_print=True)
    
    # コンテンツが登録されているかチェック
    # プレフィックスマッチング（0x形式のチャンク指定を除去してベース名で判定）
    base_name = name
    if '/0x' in base_name:
        base_name = base_name.rsplit('/0x', 1)[0]
    
    is_registered = any(
        registered.startswith(base_name) or base_name in registered
        for registered in registered_contents
    )
    
    if not is_registered:
        write_log(f"  未登録のコンテンツなので、FIB削除をスキップ", also_print=True)
        return
    
    write_log(f"  登録済みコンテンツの検証失敗を検知、FIBエントリを削除中...", also_print=True)
    
    # プレフィックスを後ろから削っていって全てのパターンで削除を試行
    prefixes_to_try = []
    current = name
    
    # 完全なnameから始める
    prefixes_to_try.append(current)
    
    # 後ろから'/'で区切りながら削っていく
    while '/' in current:
        last_slash = current.rfind('/')
        
        # '/'を含むバージョンと含まないバージョンを追加
        current_with_slash = current[:last_slash + 1]
        current_without_slash = current[:last_slash]
        
        if current_with_slash not in prefixes_to_try:
            prefixes_to_try.append(current_with_slash)
        if current_without_slash and current_without_slash not in prefixes_to_try:
            prefixes_to_try.append(current_without_slash)
        
        current = current_without_slash
    
    write_log(f"  {len(prefixes_to_try)}個のプレフィックスパターンで削除を試行", also_print=True)
    
    success_count = 0
    for prefix in prefixes_to_try:
        if not prefix:
            continue
            
        try:
            # cefrouteはシェルスクリプトなのでshell=Trueが必要
            cmd = f"cefroute del {prefix} {protocol} {host}"
            
            write_log(f"  [コマンド] {cmd}", also_print=True)
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                write_log(f"  ✓ FIBエントリを削除: {prefix}", also_print=True)
                success_count += 1
            else:
                write_log(f"  [デバッグ] プレフィックス '{prefix}' の削除失敗: {result.stderr.strip()}", also_print=True)
        except subprocess.TimeoutExpired:
            write_log(f"  ✗ cefrouteコマンドがタイムアウト: {prefix}", also_print=True)
        except Exception as e:
            write_log(f"  ✗ cefrouteの実行に失敗 ({prefix}): {e}", also_print=True)
    
    if success_count > 0:
        write_log(f"  ✓ {success_count}個のFIBエントリを削除しました", also_print=True)
        # 登録から削除
        to_remove = [c for c in registered_contents if c.startswith(base_name)]
        for c in to_remove:
            registered_contents.discard(c)
    else:
        write_log(f"  ⚠ FIBエントリは削除されませんでした", also_print=True)


def notification_listener():
    """
    検証失敗通知をリッスンするスレッド
    """
    import select
    global running
    
    write_log("検証失敗通知リスナーを起動中...", also_print=True)
    
    # 通知用FIFOが作成されるまで待機
    while running and not os.path.exists(NOTIFY_FIFO_PATH):
        time.sleep(0.5)
    
    if not running:
        return
    
    write_log(f"✓ 通知用FIFO検出: {NOTIFY_FIFO_PATH}\n", also_print=True)
    
    try:
        # 読み取り専用・ブロッキングモードで開く（効率的な待機のため）
        fifo_fd = os.open(NOTIFY_FIFO_PATH, os.O_RDONLY)
        fifo = os.fdopen(fifo_fd, 'rb')
        write_log("検証失敗通知を待機中...\n", also_print=True)
        
        try:
            while running:
                try:
                    # selectでデータが来るまで待機（タイムアウト1秒）
                    readable, _, _ = select.select([fifo_fd], [], [], 1.0)
                    if not readable:
                        continue  # タイムアウト、再チェック
                    
                    # name_len を読み取り
                    data = fifo.read(2)
                    if len(data) != 2:
                        if not running:
                            break
                        continue
                    
                    name_len = struct.unpack('!H', data)[0]
                    
                    # name を読み取り
                    name_data = fifo.read(name_len)
                    if len(name_data) != name_len:
                        write_log("警告: name データが不完全", also_print=True)
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
                        write_log("警告: host データが不完全", also_print=True)
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
                        write_log("警告: protocol データが不完全", also_print=True)
                        continue
                    protocol = protocol_data.decode('utf-8', errors='ignore')
                    
                    # 検証失敗を処理
                    handle_verification_failure(name, host, protocol)
                    
                except Exception as e:
                    if running:
                        write_log(f"通知読み取りエラー: {e}", also_print=True)
                    break
        finally:
            fifo.close()
    except Exception as e:
        if running:
            write_log(f"通知用FIFO オープン失敗: {e}", also_print=True)

def check_for_updates(contract, block_number):
    """
    全データを取得して差分を検知
    
    Returns:
        bool: 新規登録があればTrue
    """
    global known_data
    
    try:
        # コントラクトから全データを取得
        result = contract.functions.getAllEntries().call()
        keys = result[0]
        value_arrays = result[1]
        
        new_entries = []
        
        for i in range(len(keys)):
            key = keys[i].hex()
            values = value_arrays[i]
            
            # 既知のバリューを取得
            known_values = known_data.get(key, [])
            
            # 新しいバリューの検出
            for value in values:
                if value not in known_values:
                    new_entries.append({'key': '0x' + key, 'value': value})
            
            # データを更新
            known_data[key] = values
        
        # 新規登録があった場合のみ通知
        if new_entries:
            print(f"\n[ブロック {block_number}] 新規登録を検知:")
            for entry in new_entries:
                print(f"  キー: {entry['key']}")
                print(f"  バリュー: {entry['value']}")
                # cefnetdに登録
                add_verification_entry_to_fifo(entry['key'], entry['value'])
        
        return len(new_entries) > 0
        
    except Exception as e:
        print(f"エラー: データ取得に失敗 - {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False

def watch_blocks(w3, contract):
    """新しいブロックをポーリングで監視"""
    global last_block_number
    
    write_log("ブロック監視を開始...", also_print=True)
    write_log(f"コントラクトアドレス: {contract.address}", also_print=True)
    write_log(f"ポーリング間隔: {POLL_INTERVAL}秒", also_print=True)
    write_log(f"FIFO パス: {FIFO_PATH}", also_print=True)
    
    # FIFOの存在を確認
    if os.path.exists(FIFO_PATH):
        write_log(f"✓ FIFO検出済み", also_print=True)
    else:
        write_log(f"⚠ FIFO未検出（cefnetd起動後に利用可能になります）", also_print=True)
    
    write_log("更新を待機中...\n", also_print=True)
    
    # 初期データの読み込み（既存データもパイプに書き込む）
    current_block = w3.eth.block_number
    last_block_number = current_block
    
    # 初期データを読み込み、パイプに書き込む
    try:
        result = contract.functions.getAllEntries().call()
        keys = result[0]
        value_arrays = result[1]
        
        if len(keys) > 0:
            print(f"[初期化] 既存エントリ: {len(keys)}件")
        
        for i in range(len(keys)):
            key = keys[i].hex()
            values = value_arrays[i]
            known_data[key] = values
            
            # 既存データもパイプに書き込む
            for value in values:
                print(f"  既存データを登録: 0x{key} -> {value}")
                add_verification_entry_to_fifo('0x' + key, value)
                time.sleep(0.01)  # cefnetd側の読み取りを待つ（10ms）
        
    except Exception as e:
        print(f"警告: 初期データ取得失敗 - {str(e)}", file=sys.stderr)
    
    # ポーリングループ
    while True:
        try:
            current_block = w3.eth.block_number
            
            if current_block > last_block_number:
                # 差分があった場合のみ通知（新規データはFIFOに書き込む）
                check_for_updates(contract, current_block)
                last_block_number = current_block
            
            time.sleep(POLL_INTERVAL)
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"エラー: ポーリング中にエラーが発生 - {str(e)}", file=sys.stderr)
            time.sleep(POLL_INTERVAL)

def main():
    """メイン処理"""
    global running, verify_fifo
    
    # ログファイルの初期化
    try:
        with open(LOG_FILE_PATH, 'w') as f:
            f.write(f"=== get_update.py ログ開始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        print(f"ログファイル: {LOG_FILE_PATH}")
    except Exception as e:
        print(f"警告: ログファイルの初期化に失敗 - {e}", file=sys.stderr)
    
    try:
        # 検証用FIFOを開く（FIFOが作成されるまで待機）
        write_log("検証用FIFOを待機中...", also_print=True)
        max_wait = 30
        for i in range(max_wait):
            if os.path.exists(FIFO_PATH):
                break
            if i < max_wait - 1:
                time.sleep(1)
            else:
                write_log(f"エラー: {FIFO_PATH} が見つかりません", also_print=True)
                sys.exit(1)
        
        # FIFOを書き込みモード・ブロッキングで開く（書き込みが完了するまで待機）
        fifo_fd = os.open(FIFO_PATH, os.O_WRONLY)
        verify_fifo = os.fdopen(fifo_fd, 'wb', buffering=0)  # バッファリングなし
        write_log(f"✓ 検証用FIFOを開きました: {FIFO_PATH}\n", also_print=True)
        
        # HTTP接続
        write_log("Ethereumノードに接続中...", also_print=True)
        w3 = Web3(Web3.HTTPProvider(HTTP_URL))
        
        if not w3.is_connected():
            write_log("エラー: HTTP接続に失敗しました", also_print=True)
            sys.exit(1)
        
        write_log("✓ 接続成功\n", also_print=True)
        
        # コントラクト情報の読み込み
        contract_info = load_contract_info()
        write_log(f"コントラクトアドレス: {contract_info['address']}", also_print=True)
        
        contract = w3.eth.contract(
            address=contract_info['address'],
            abi=contract_info['abi']
        )
        write_log("✓ コントラクトオブジェクト作成完了", also_print=True)
        
        # 通知リスナーをバックグラウンドで起動
        write_log("通知リスナーを起動します", also_print=True)
        listener_thread = threading.Thread(target=notification_listener, daemon=True)
        listener_thread.start()
        
        # ブロック監視を開始
        write_log("ブロック監視を開始します\n", also_print=True)
        watch_blocks(w3, contract)
        
    except KeyboardInterrupt:
        print("\n\n監視を停止します...")
        running = False
    except Exception as e:
        print(f"致命的エラー: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        running = False
        sys.exit(1)
    finally:
        # 検証用FIFOを閉じる
        if verify_fifo is not None:
            try:
                verify_fifo.close()
                write_log("検証用FIFOをクローズしました", also_print=True)
            except Exception as e:
                write_log(f"FIFO クローズエラー: {e}", also_print=True)

if __name__ == '__main__':
    main()
