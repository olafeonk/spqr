package config

import (
	"context"
	"errors"
	"fmt"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type RADIUSCfg struct {
	Conns []RadiusConn `json:"radius_conn_config" yaml:"radius_conn_config" toml:"radius_conn_config"`
}

type RadiusConn struct {
	Server string `json:"server" yaml:"server" toml:"server"`
	Secret string `json:"secret" yaml:"secret" toml:"secret"`
	Port   int    `json:"port" yaml:"port" toml:"port"`
}

func (r *RADIUSCfg) IsAuthUser(username, password string) error {
	for _, conn := range r.Conns {
		packet := radius.New(radius.CodeAccessRequest, []byte(conn.Secret))
		err := rfc2865.UserName_SetString(packet, username)
		if err != nil {
			return err
		}
		err = rfc2865.UserPassword_SetString(packet, password)
		if err != nil {
			return err
		}
		response, err := radius.Exchange(context.Background(), packet, fmt.Sprintf("%s:%d", conn.Server, conn.Port))
		if err != nil {
			return err
		}
		if response.Code == radius.CodeAccessAccept {
			return nil
		}
	}
	return errors.New("not found")
}
