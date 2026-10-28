"""Node EVM giả lập (synthetic=true) để test collector.
GET /mine?n=3 | GET /reorg?from=5 | GET /fail?n=3 | GET /fail429?n=2&sec=1 | GET /reset
"""
import json, hashlib, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

T0 = 1790812800  # 2026-10-01T00:00:00Z
TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDC_ADDR = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

chain = []
seed = {"v": 0}
fails = {"n": 0, "code": 503, "retry_after": None}
features = {"block_receipts": False}
receipt_map = {}

def pad_addr(addr):
    raw = addr.lower().replace("0x", "")
    return "0x" + raw.rjust(64, "0")

def pad_uint256(val):
    raw = hex(val)[2:]
    return "0x" + raw.rjust(64, "0")

def mk(n, parent):
    h = "0x" + hashlib.sha256(f"{seed['v']}-{n}-{parent}".encode()).hexdigest()
    txs = []
    num_txs = 2 if n % 2 else 1
    for i in range(num_txs):
        tx_hash = "0x" + hashlib.sha256(f"tx{seed['v']}-{n}-{i}".encode()).hexdigest()
        from_addr = "0x%040x" % (i + 1)
        # Block 4 có 1 transaction contract creation (to = None, gửi kèm 1 ETH)
        if n == 4 and i == 0:
            to_addr = None
            contract_addr = "0x%040x" % (9999)
            val = 1 * 10**18
        else:
            to_addr = "0x%040x" % (n + 100)
            contract_addr = None
            val = (i + 1) * 10**18 * (50 if n == 7 else 1)

        tx = {
            "hash": tx_hash,
            "from": from_addr,
            "to": to_addr,
            "value": hex(val),
            "nonce": hex(n),
            "input": "0x",
            "transactionIndex": hex(i),
            "blockNumber": hex(n),
            "blockHash": h
        }
        txs.append(tx)

        logs = []
        # Ở các block chia hết cho 3 (ví dụ block 3, 6, 9), thêm 1 ERC-20 Transfer log
        if n > 0 and n % 3 == 0 and i == 0:
            erc20_amount = (n * 1000) * 10**6  # 3000 USDC, 6000 USDC...
            logs.append({
                "address": USDC_ADDR,
                "topics": [
                    TRANSFER_TOPIC0,
                    pad_addr(from_addr),
                    pad_addr("0x%040x" % (n + 200))
                ],
                "data": pad_uint256(erc20_amount),
                "blockNumber": hex(n),
                "transactionHash": tx_hash,
                "transactionIndex": hex(i),
                "blockHash": h,
                "logIndex": "0x0",
                "removed": False
            })

        receipt_map[tx_hash] = {
            "transactionHash": tx_hash,
            "blockHash": h,
            "blockNumber": hex(n),
            "transactionIndex": hex(i),
            "status": "0x1",
            "gasUsed": "0x5208",
            "contractAddress": contract_addr,
            "logs": logs
        }

    return {"number": hex(n), "hash": h, "parentHash": parent, "timestamp": hex(T0 + n * 3600), "transactions": txs}

def mine(k=1):
    for _ in range(k):
        chain.append(mk(len(chain), chain[-1]["hash"] if chain else "0x" + "00" * 32))

def reset():
    global chain, receipt_map
    chain = []
    receipt_map = {}
    seed["v"] = 0
    fails["n"] = 0
    fails["code"] = 503
    fails["retry_after"] = None
    features["block_receipts"] = False
    mine(12)

reset()

def receipt(h):
    return receipt_map.get(h)

def process_rpc_call(req):
    req_id = req.get("id", 1)
    m = req.get("method")
    p = req.get("params", [])

    if m == "eth_chainId":
        return {"jsonrpc": "2.0", "id": req_id, "result": hex(31337)}
    elif m == "eth_blockNumber":
        return {"jsonrpc": "2.0", "id": req_id, "result": hex(len(chain) - 1)}
    elif m == "eth_getBlockByNumber":
        n = int(p[0], 16) if isinstance(p[0], str) and p[0].startswith("0x") else int(p[0])
        res = chain[n] if n < len(chain) else None
        if res and len(p) > 1 and not p[1]:
            res = {**res, "transactions": [t["hash"] for t in res["transactions"]]}
        return {"jsonrpc": "2.0", "id": req_id, "result": res}
    elif m == "eth_getTransactionReceipt":
        return {"jsonrpc": "2.0", "id": req_id, "result": receipt(p[0])}
    elif m == "eth_getBlockReceipts":
        if not features["block_receipts"]:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "the method eth_getBlockReceipts does not exist/is not available"}}
        n = int(p[0], 16) if isinstance(p[0], str) and p[0].startswith("0x") else int(p[0])
        if n >= len(chain):
            return {"jsonrpc": "2.0", "id": req_id, "result": None}
        blk = chain[n]
        receipts = [receipt_map.get(t["hash"]) for t in blk["transactions"]]
        return {"jsonrpc": "2.0", "id": req_id, "result": receipts}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"unsupported method {m}"}}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, o, code=200, extra_headers=None):
        d = json.dumps(o).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(d)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(d)

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/mine":
            mine(int(q.get("n", [1])[0]))
        elif u.path == "/reorg":
            f = int(q["from"][0]); seed["v"] += 1; del chain[f:]; mine(4)
        elif u.path == "/fail":
            fails["n"] = int(q.get("n", [1])[0])
            fails["code"] = 503
            fails["retry_after"] = None
        elif u.path == "/fail429":
            fails["n"] = int(q.get("n", [1])[0])
            fails["code"] = 429
            fails["retry_after"] = q.get("sec", ["1"])[0]
        elif u.path == "/toggle_block_receipts":
            features["block_receipts"] = bool(int(q.get("enabled", ["1"])[0]))
        elif u.path == "/reset":
            reset()
        self._send({"height": len(chain) - 1, "block_receipts": features["block_receipts"]})

    def do_POST(self):
        if fails["n"] > 0:
            fails["n"] -= 1
            extra = {}
            if fails["retry_after"] is not None:
                extra["Retry-After"] = fails["retry_after"]
            return self._send({"error": "rate limit or server down"}, code=fails["code"], extra_headers=extra)

        content_len = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_len))
        if isinstance(body, list):
            res = [process_rpc_call(req) for req in body]
        else:
            res = process_rpc_call(body)
        self._send(res)

def run_server(port=8545):
    server = HTTPServer(("127.0.0.1", port), H)
    server.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8545
    run_server(port)
