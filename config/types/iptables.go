// Copyright 2017 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"errors"
	"fmt"

	ignTypes "github.com/coreos/ignition/config/v2_0/types"
	"github.com/coreos/ignition/config/validate/report"
	"github.com/vincent-petithory/dataurl"
)

var (
	ErrInvalidIptablesDefault = errors.New("iptables chain default must be one of ACCEPT or DROP")
	ErrEmptyTableName         = errors.New("table cannot be empty")
)

type Iptables struct {
	V4 []iptablesTable `yaml:"v4"`
	V6 []iptablesTable `yaml:"v6"`
}

type iptablesTable struct {
	Table   string         `yaml:"table"`
	Input   *iptablesRules `yaml:"input"`
	Forward *iptablesRules `yaml:"forward"`
	Output  *iptablesRules `yaml:"output"`
}

type iptablesRules struct {
	Default iptablesDefault `yaml:"default"`
	Rules   []string        `yaml:"rules"`
}

type iptablesDefault string

func (id iptablesDefault) Validate() report.Report {
	switch id {
	case "ACCEPT", "DROP", "":
		return report.Report{}
	default:
		return report.ReportFromError(ErrInvalidIptablesDefault, report.EntryError)
	}
}

func (it iptablesTable) Validate() report.Report {
	if it.Table == "" {
		return report.ReportFromError(ErrEmptyTableName, report.EntryError)
	}
	return report.Report{}
}

func init() {
	register2_0(func(in Config, out ignTypes.Config, platform string) (ignTypes.Config, report.Report) {
		if in.Iptables == nil {
			return out, report.Report{}
		}
		if len(in.Iptables.V4) > 0 {
			out.Storage.Files = append(out.Storage.Files, ignTypes.File{
				Filesystem: "root",
				Path:       "/var/lib/iptables/rules-save",
				Mode:       0420,
				Contents:   iptablesContents(in.Iptables.V4),
			})
			out.Systemd.Units = append(out.Systemd.Units, ignTypes.SystemdUnit{
				Name:   "iptables-restore.service",
				Enable: true,
			})
			out.Systemd.Units = append(out.Systemd.Units, ignTypes.SystemdUnit{
				Name:   "iptables-store.service",
				Enable: true,
			})
		}
		if len(in.Iptables.V6) > 0 {
			out.Storage.Files = append(out.Storage.Files, ignTypes.File{
				Filesystem: "root",
				Path:       "/var/lib/ip6tables/rules-save",
				Mode:       0420,
				Contents:   iptablesContents(in.Iptables.V6),
			})
			out.Systemd.Units = append(out.Systemd.Units, ignTypes.SystemdUnit{
				Name:   "ip6tables-restore.service",
				Enable: true,
			})
			out.Systemd.Units = append(out.Systemd.Units, ignTypes.SystemdUnit{
				Name:   "ip6tables-store.service",
				Enable: true,
			})
		}
		return out, report.Report{}
	})
}

func iptablesContents(chains []iptablesTable) ignTypes.FileContents {
	contents := ""
	for _, c := range chains {
		contents += fmt.Sprintf("*%s\n", c.Table)
		for _, s := range []struct {
			Name string
			r    *iptablesRules
		}{
			{"INPUT", c.Input},
			{"FORWARD", c.Forward},
			{"OUTPUT", c.Output},
		} {
			if s.r == nil {
				continue
			}
			if s.r.Default == "" {
				s.r.Default = "DROP"
			}
			contents += fmt.Sprintf(":%s %s [0:0]\n", s.Name, s.r.Default)
			for _, r := range s.r.Rules {
				contents += fmt.Sprintf("%s\n", r)
			}
		}
	}
	contents += "COMMIT\n# EOF\n"
	fmt.Printf("rules:\n%s\n", contents)
	return ignTypes.FileContents{
		Source: ignTypes.Url{
			Scheme: "data",
			Opaque: "," + dataurl.EscapeString(contents),
		},
	}
}
