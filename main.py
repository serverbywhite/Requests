#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import os, json

app = Flask(__name__)
FILE = "data.json"
OWNER = "MinhAnhs"

# Tạo file nếu chưa có
if not os.path.exists(FILE):
    with open(FILE, "w") as f:
        json.dump({}, f, indent=2)

def read_data():
    with open(FILE, "r") as f:
        return json.load(f)

def write_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=2)

# GET
@app.route("/api/data", methods=["GET"])
def get_data():
    return jsonify(read_data()), 200

# POST
@app.route("/api/data", methods=["POST"])
def create_data():
    data = read_data()
    new = request.get_json(force=True)
    data.update(new)
    write_data(data)
    return jsonify({"msg": "Đã thêm dữ liệu"}), 201

# PUT
@app.route("/api/data", methods=["PUT"])
def update_data():
    key = request.args.get("key")
    value = request.args.get("value")
    owner = input("Nhập tên chủ điều khiển: ").strip()
    if owner != OWNER:
        return jsonify({"error": "Không có quyền sửa"}), 403
    data = read_data()
    if key not in data:
        return jsonify({"error": "Không tìm thấy key"}), 404
    data[key] = value
    write_data(data)
    return jsonify({"msg": f"Đã sửa {key} thành {value}"}), 200

# DELETE
@app.route("/api/data", methods=["DELETE"])
def delete_data():
    key = request.args.get("key")
    data = read_data()
    if key not in data:
        return jsonify({"error": "Không tìm thấy key"}), 404
    del data[key]
    write_data(data)
    return jsonify({"msg": f"Đã xóa {key}"}), 200

if __name__ == "__main__":
    from flask import cli
    cli.show_server_banner = lambda *x: None
    host = "0.0.0.0"
    port = 5000
    print(f"API chạy tại: http://{host}:{port}/api/data")
    app.run(host=host, port=port)
