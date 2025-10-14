#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import os, json

app = Flask(__name__)
FILE = "data.json"
OWNER = "MinhAnhs"

# Khởi tạo file trống dạng list
if not os.path.exists(FILE):
    with open(FILE, "w") as f:
        json.dump([], f, indent=2)

def read_data():
    with open(FILE, "r") as f:
        return json.load(f)

def write_data(data):
    with open(FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

@app.route("/api/data", methods=["GET"])
def get_data():
    return jsonify(read_data()), 200

@app.route("/api/data", methods=["POST"])
def add_data():
    new_data = request.get_json()
    try:
        data = read_data()
    except Exception:
        data = []

    data.append(new_data)  # Thêm nội dung nhận từ client
    write_data(data)

    return jsonify({"msg": "Đã thêm dữ liệu"}), 200

@app.route("/api/data", methods=["PUT"])
def update_data():
    key = request.args.get("key")
    value = request.args.get("value")
    owner = input("Nhập tên chủ điều khiển: ").strip()
    if owner != OWNER:
        return jsonify({"error": "Không có quyền sửa"}), 403
    data = read_data()
    for record in data:
        if key in record:
            record[key] = value
            write_data(data)
            return jsonify({"msg": f"Đã sửa {key} thành {value}"}), 200
    return jsonify({"error": "Không tìm thấy key"}), 404

@app.route("/api/data", methods=["DELETE"])
def delete_data():
    key = request.args.get("key")
    data = read_data()
    for record in data:
        if key in record:
            data.remove(record)
            write_data(data)
            return jsonify({"msg": f"Đã xóa {key}"}), 200
    return jsonify({"error": "Không tìm thấy key"}), 404

if __name__ == "__main__":
    os.system('clear')
    print("Dịch vụ API by JunidoKai")
    from flask import cli
    cli.show_server_banner = lambda *x: None
    print("API chạy tại: http://0.0.0.0:5000/api/data")
    app.run(host="0.0.0.0", port=5000)
