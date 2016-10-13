package shadowsocks

type Config struct {
	Server         interface{} `json:"server"`
	ServerPort     int         `json:"server_port"`
	LocalPort      int         `json:"local_port"`
	Password       string      `json:"password"`
	Method         string      `json:"method"`
	Auth           bool        `json:"auth"`

	PortPassword   map[string]string `json:"port_password"`
	Timeout        int               `json:"timeout"`

	ServerPassword [][]string `json:"server_password"`
}
