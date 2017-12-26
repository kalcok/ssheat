package main

import (
	"github.com/kalcok/ssheat"
	"github.com/kalcok/jc/tools"
)


func main()  {
	ssheat.InitRegexp()
	mongoConf := tools.SessionConf{Addrs: []string{"linux.dev"}, Database:"ssheat"}

	tools.InitSession(&mongoConf)
	defer tools.CloseSession()
	ssheat.WatchFile("/tmp/auth.log")
}
