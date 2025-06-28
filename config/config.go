package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/mat285/linklan/log"
)

const (
	DefaultPrimaryCIDR   = "192.168.1.0/24"
	DefaultSecondaryCIDR = "192.168.0.0/24"
)

type Config struct {
	Lan        Lan     `yaml:"lan,omitempty" json:"lan,omitempty"`
	Interfaces []IFace `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
	Routing    Routing `yaml:"routing,omitempty" json:"routing,omitempty"`

	Logger log.Config `yaml:"logger,omitempty" json:"logger,omitempty"`
}

type Lan struct {
	CIDR           string   `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Iface          string   `yaml:"iface,omitempty" json:"iface,omitempty"`
	SecondaryCIDRs []string `yaml:"secondaryCidrs,omitempty" json:"secondaryCidrs,omitempty"`
}

type IFace struct {
	IFaceIndentifier `yaml:",inline" json:",inline"`
	Match            IFaceIndentifier `yaml:"match,omitempty" json:"match,omitempty"`
	IP               string           `yaml:"ip,omitempty" json:"ip,omitempty"`
	Priority         int              `yaml:"priority,omitempty" json:"priority,omitempty"`
	Disabled         bool             `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

func (i IFace) MatchesName(name string) bool {
	if !i.Match.IsZero() {
		return i.Match.MatchesName(name, true)
	}
	return i.IFaceIndentifier.MatchesName(name, false)
}

type IFaceIndentifier struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	Mac  string `yaml:"mac,omitempty" json:"mac,omitempty"`
}

func (i IFaceIndentifier) IsZero() bool {
	return i.Name == "" && i.Mac == ""
}

func (i IFaceIndentifier) MatchesName(name string, regex bool) bool {
	if regex {
		r, err := regexp.Compile(i.Name)
		if err != nil {
			return false // Invalid regex, treat as no match
		}
		return r.MatchString(name)
	}
	return i.Name == name
}

type Routing struct {
	AdditionalCIDRs []string `yaml:"additionalCidrs,omitempty" json:"additionalCidrs,omitempty"`
	Bonding         Bonding  `yaml:"bonding,omitempty" json:"bonding,omitempty"`
	Routes          []Route  `yaml:"routes,omitempty" json:"routes,omitempty"`
}

type Route struct {
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	Iface       string `yaml:"iface,omitempty" json:"iface,omitempty"`
}

type Bonding struct {
	Mode          string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Ifaces        []string `yaml:"ifaces,omitempty" json:"ifaces,omitempty"`
	AllInterfaces bool     `yaml:"allInterfaces,omitempty" json:"allInterfaces,omitempty"`
	Enabled       bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

func (c *Config) String() string {
	if c == nil {
		return "Config(nil)"
	}
	data, _ := json.Marshal(c)
	return string(data)
}

func (c *Config) SetDefaults() {
	if c.Lan.CIDR == "" {
		c.Lan.CIDR = DefaultPrimaryCIDR
	}
}

func (c *Config) Resolve(ctx context.Context) (context.Context, error) {
	c.SetDefaults()
	ctx = log.WithLogger(ctx, log.New(c.Logger))
	if _, err := ParseCidr(c.Lan.CIDR); err != nil {
		return nil, fmt.Errorf("invalid primary CIDR [%q]: %w", c.Lan.CIDR, err)
	}

	for i, cidr := range c.Lan.SecondaryCIDRs {
		if _, err := ParseCidr(cidr); err != nil {
			return nil, fmt.Errorf("invalid secondary CIDR  index %d [%q]: %w", i, cidr, err)
		}
	}

	for i, iface := range c.Interfaces {
		if iface.Match.IsZero() && iface.IFaceIndentifier.IsZero() {
			return nil, fmt.Errorf("interface %d must have either match or iface identifier set", i)
		}
		if !iface.Match.IsZero() && !iface.IFaceIndentifier.IsZero() {
			return nil, fmt.Errorf("interface %d cannot have both match and iface identifier set", i)
		}
		if !iface.Match.IsZero() {
			if iface.Match.Name != "" {
				_, err := regexp.Compile(iface.Match.Name)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for interface %d [%q]: %w", i, iface.Match.Name, err)
				}
			}
			if iface.Match.Mac != "" {
				_, err := regexp.Compile(iface.Match.Mac)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for MAC address in interface %d [%q]: %w", i, iface.Match.Mac, err)
				}
			}
		}
		if iface.IP != "" {
			valid := net.ParseIP(iface.IP)
			if valid == nil {
				return nil, fmt.Errorf("invalid IP for interface %d [%q]", i, iface.IP)
			}
		}
	}

	for i, route := range c.Routing.Routes {
		if route.Destination == "" {
			return nil, fmt.Errorf("route %d must have a destination", i)
		}
		if route.Iface == "" {
			return nil, fmt.Errorf("route %d must have an interface", i)
		}
		if _, err := ParseCidr(route.Destination); err != nil {
			return nil, fmt.Errorf("invalid route destination %d [%q]: %w", i, route.Destination, err)
		}
	}
	if c.Routing.Bonding.Enabled {
		return nil, fmt.Errorf("bonding is not supported yet")
	}
	return ctx, nil
}

func ParseCidr(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	bits, _ := ipNet.Mask.Size()
	switch bits {
	case 8, 16, 24:
	default:
		return "", fmt.Errorf("unsupported CIDR size: %s bits: %d", cidr, bits)
	}
	return ipNet.String(), nil
}
