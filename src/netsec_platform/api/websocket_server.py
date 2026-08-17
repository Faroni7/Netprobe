"""
WebSocket Server
Real-time communication.
"""
class WebSocketServer:
    def __init__(self):
        self.clients = []

    def broadcast(self, message: str):
        for client in self.clients:
            client.send(message)
