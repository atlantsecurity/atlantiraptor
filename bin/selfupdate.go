package main

import (
	"fmt"

	kingpin "github.com/alecthomas/kingpin/v2"
	"www.velocidex.com/golang/velociraptor/config"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
)

var (
	selfupdate_command = app.Command(
		"selfupdate", "Self-update helpers (used by the server's updater).").Hidden()

	selfupdate_version_command = selfupdate_command.Command(
		"version", "Print the Atlantiraptor release version of this binary.")

	selfupdate_verify_command = selfupdate_command.Command(
		"verify", "Check a binary the way the updater does before installing it.")
	selfupdate_verify_file = selfupdate_verify_command.Arg(
		"file", "The binary to check.").Required().String()

	selfupdate_restart_service_command = selfupdate_command.Command(
		"restart-service", "Start the server service again after an update.")
	selfupdate_restart_service_name = selfupdate_restart_service_command.Flag(
		"name", "Service name.").Required().String()
)

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case selfupdate_version_command.FullCommand():
			fmt.Println(config.ReleaseVersion())

		case selfupdate_verify_command.FullCommand():
			subject, err := selfupdate.VerifyBinary(*selfupdate_verify_file)
			kingpin.FatalIfError(err, "%v", *selfupdate_verify_file)
			fmt.Printf("OK: %v is signed by %v and trusted by Windows.\n",
				*selfupdate_verify_file, subject)

		case selfupdate_restart_service_command.FullCommand():
			err := selfupdate.RestartService(*selfupdate_restart_service_name)
			kingpin.FatalIfError(err, "Restarting service %v", *selfupdate_restart_service_name)

		default:
			return false
		}
		return true
	})
}
