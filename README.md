# Distributed File Transfer System with Monitoring Dashboard

## Overview

This project is a distributed file transfer system that enables clients to **upload**, **download**, and **manage files** on a centralized server. It uses **multiple network protocols**—TCP, UDP, and HTTP—and includes a real-time **web-based dashboard** for monitoring server statistics.

The system is designed for educational purposes and showcases how to build a scalable, multi-threaded server with discovery and monitoring capabilities.

---

## Features

### ✅ Multi-threaded TCP File Server (Port `8888`)

* Handles **multiple clients concurrently** using `TcpListener` and async I/O.
* Performs user **authentication**, and supports:

  * `list` command (shows all available files with metadata),
  * `upload` and `download` operations (with progress display).
* Uses `ConcurrentDictionary` to safely track client connections and states.
* Cleans up resources properly when clients disconnect.

### ✅ UDP Status Broadcasting (Port `8889`)

* Every **5 seconds**, the server sends out a **JSON-formatted broadcast** with:

  * Server name
  * Number of active connections
  * Port information
* Clients listen for broadcasts for 5 seconds at startup to **automatically discover available servers**.

### ✅ HTTP Monitoring Dashboard (Port `8080`)

* Accessible via any web browser at [`http://localhost:8080`](http://localhost:8080).
* Displays:

  * Server uptime
  * Active connections
  * Storage usage
* Built-in **auto-refresh** to show real-time stats using meta-refresh or JavaScript.

### ✅ Client Application

* Connects to server via:

  * **Automatic discovery** (via UDP),
  * Or **manual IP entry**.
* Handles:

  * Authentication
  * `list`, `upload`, and `download` commands
* Displays **transfer progress** for file operations.

---

## Running the System

### 🖥️ Starting the Server

* Run the server app. You should see:

  * `TCP File Server started on port 8888`
  * `HTTP monitoring server started on port 8080`

### 🧑‍💻 Starting a Client

* The client will attempt to discover a server via UDP.
* If found, it will connect automatically.
* Otherwise, it will ask for manual input (IP and port).

### 📊 Using the Dashboard

* Open your browser and go to:

  * [`http://localhost:8080`](http://localhost:8080) (for local testing)
  * Or `http://<server-ip>:8080` (for remote access)
* You'll see:

  * Server connection statistics
  * A table of active client sessions

---

## Folder Structure

* `Server/`: Source code for the server
* `Client/`: Source code for the client
* `Dashboard/`: HTML/JS files for the HTTP monitoring dashboard

> 📝 *Note:* You’ll find `// TODO` comments in the starter code—these indicate where you need to add or complete functionality based on your understanding and what you’ve learned during lab sessions.

---

## Resources

Starter code & dashboard page:
🔗 [Google Drive – Starter Code and Dashboard](https://drive.google.com/drive/folders/1H1Djg7LvM0acDCyqTAVt8aQos1aEIViI?usp=sharing)

---

## Technologies Used

* C# (.NET)
* TCP / UDP sockets
* HTTP Server (`HttpListener`)
* JSON for server discovery
* Multi-threading (`Task`, `async/await`)
* HTML + JavaScript (for dashboard)
