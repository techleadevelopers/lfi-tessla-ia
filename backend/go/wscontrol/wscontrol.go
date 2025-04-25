package wscontrol

import (
	"encoding/json"
	"log"
	"time"
	"github.com/gorilla/websocket"
)

// Client encapsula a conexão WebSocket
type Client struct {
	conn *websocket.Conn
}

// Connect abre a conexão WS e retorna um client
func Connect(url string) (*Client, error) {
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c}, nil
}

// Log envia um evento com nome e dados arbitrários
func (c *Client) Log(event string, data ...interface{}) error {
	msg := map[string]interface{}{
		"event": event,
		"data":  data,
		"time":  time.Now().UTC(),
	}
	if b, err := json.Marshal(msg); err == nil {
		err := c.conn.WriteMessage(websocket.TextMessage, b)
		if err != nil {
			log.Println("wscontrol write error:", err)
			return err
		}
	} else {
		log.Println("wscontrol marshal error:", err)
		return err
	}
	return nil
}

// Close encerra a conexão
func (c *Client) Close() error {
	return c.conn.Close()
}
