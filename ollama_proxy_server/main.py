import asyncio
import aiohttp
from aiohttp import web
import configparser
from pathlib import Path
import csv
import datetime
import argparse
import json

# Configuration
def get_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return [(name, {'url': config[name]['url']}) for name in config.sections()]

# Read the authorized users and their keys from a file
def get_authorized_users(filename):
    authorized_users = {}
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.strip():
                try:
                    user, key = line.strip().split(':')
                    authorized_users[user] = key
                except:
                    print(f"User entry broken: {line.strip()}")
    return authorized_users

# Middleware for authentication
@web.middleware
async def auth_middleware(request, handler):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return web.Response(text="Unauthorized", status=403)
    token = auth_header.split(' ')[1]
    user, key = token.split(':')
    if authorized_users.get(user) == key:
        request['user'] = user
        return await handler(request)
    return web.Response(text="Unauthorized", status=403)

# Asynchronous request handler for each server
async def process_request(server_url, request_data, endpoint):
    async with aiohttp.ClientSession() as session:
        try:
            url = f"{server_url}{endpoint}"
            async with session.post(url, json=request_data) as resp:
                response_data = await resp.json()
                return response_data
        except aiohttp.ClientError as e:
            print(f"Error communicating with {server_url}: {e}")
            return {"error": "Server communication error"}

# Add log entry
def add_access_log_entry(log_path, event, user, ip_address, access, server, nb_queued_requests, error=""):
    log_file_path = Path(log_path)
    if not log_file_path.exists():
        with open(log_file_path, mode='w', newline='') as csvfile:
            fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests', 'error']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
    
    with open(log_file_path, mode='a', newline='') as csvfile:
        fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        row = {
            'time_stamp': str(datetime.datetime.now()), 
            'event': event, 
            'user_name': user, 
            'ip_address': ip_address, 
            'access': access, 
            'server': server, 
            'nb_queued_requests': nb_queued_requests, 
            'error': error
        }
        writer.writerow(row)

# Handle incoming requests and add them to the shared queue
async def handle_request(request, shared_queue, context):
    data = await request.json()
    user = request.get('user', 'unknown')
    client_ip = request.remote


    endpoint = request.path

    # Log the request
    add_access_log_entry(context['log_path'], f"request_before_api", user, client_ip, "Authorized", endpoint, shared_queue.qsize())


    future_response = asyncio.Future()
    await shared_queue.put((data, request, future_response))
    response_data = await future_response
    return web.json_response(response_data)

# Process each shared queue asynchronously
async def process_shared_queue(server_name, server_info, shared_queue, context):
    while True:
        data, request, future_response = await shared_queue.get()
        user = request.get('user', 'unknown')
        client_ip = request.remote

        
        # Determine the endpoint type based on the request path
        endpoint = request.path
        
        response_data = await process_request(server_info['url'], data, endpoint)
        add_access_log_entry(context['log_path'], f"{endpoint}_done", user, client_ip, "Authorized", server_name, shared_queue.qsize())
        shared_queue.task_done()
        future_response.set_result(response_data)

# Main function to start the server and the consumers
async def main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the config file')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the authorized users list')
    parser.add_argument('--port', type=int, default=8000, help='Port number for the server')
    args = parser.parse_args()

    # Load servers and users
    global servers
    servers = get_config(args.config)
    global authorized_users
    authorized_users = get_authorized_users(args.users_list)

    # Create context
    global context
    context = {
        'log_path': args.log_path
    }

    # Create shared queues
    global shared_queue
    shared_queue = asyncio.Queue()

    # Create server consumers for the shared queue
    for server_name, server_info in servers:
        asyncio.create_task(process_shared_queue(server_name, server_info, shared_queue, context))

    # Start the web server
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_route('*', '/{tail:.*}', lambda request: handle_request(request, shared_queue, context))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, port=args.port)
    await site.start()
    print(f"Server running on port {args.port}")

    await asyncio.Event().wait()  # Keep the server running

if __name__ == '__main__':
    asyncio.run(main())
