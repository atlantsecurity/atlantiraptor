package main

import (
	"fmt"
	"os"
	"path/filepath"

	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services/auditlog"
	"www.velocidex.com/golang/velociraptor/startup"
)

var (
	audit_command = app.Command(
		"audit", "The tamper-evident audit log on this server's disk.")

	audit_verify_command = audit_command.Command(
		"verify", "Check that no audit log entry was changed, removed or added.")
	audit_verify_dir = audit_verify_command.Flag(
		"dir", "The audit log directory (default: the server's configured one).").String()
	audit_verify_key = audit_verify_command.Flag(
		"key", "The server's audit public key (base64, shown in the console), to check a copy without the server configuration.").String()
	audit_verify_quiet = audit_verify_command.Flag(
		"quiet", "Print only problems and the verdict.").Bool()
)

func doAuditVerify() error {
	logging.DisableLogging()

	config_obj, err := makeDefaultConfigLoader().
		WithNullLoader().LoadAndValidate()
	if err != nil {
		return fmt.Errorf("Unable to load config: %w", err)
	}

	ctx, cancel := Install_sig_handler()
	defer cancel()

	if config_obj.Frontend != nil {
		sm, err := startup.StartToolServices(ctx, config_obj)
		if err != nil {
			return err
		}
		defer sm.Close()
	}

	dir := *audit_verify_dir
	if dir != "" {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	r, info, err := auditlog.VerifyWithConfig(ctx, config_obj, dir, *audit_verify_key)
	if err != nil {
		return err
	}

	if !*audit_verify_quiet {
		fmt.Printf("Directory:    %v\n", info.Directory)
		fmt.Printf("Files:        %v\n", r.Files)
		fmt.Printf("Entries:      %v (%v to %v)\n", r.Entries, r.FirstTime, r.LastTime)
		fmt.Printf("Checkpoints:  %v signed, last at entry %v; %v entries after it\n",
			r.Checkpoints, r.LastCheckpointSeq, r.UnsignedTail)
		fmt.Printf("Signing keys: %v\n", r.KeyIds)
		if info.KeyId != "" {
			fmt.Printf("Trusted key:  %v\n", info.KeyId)
		} else {
			fmt.Printf("Trusted key:  none (pass --config or --key to check who signed the log)\n")
		}
		if info.HasAnchor {
			fmt.Printf("Datastore:    checked against the position the server recorded\n")
		}
		fmt.Printf("Head:         %v\n", r.Head)
	}
	for _, p := range r.Problems {
		where := ""
		if p.File != "" {
			where = " [" + p.File + "]"
		}
		fmt.Printf("%-7s %v%v\n", p.Severity+":", p.Message, where)
	}
	if r.Ok {
		fmt.Printf("OK: the audit log is intact (%v errors, %v warnings).\n", r.Errors, r.Warnings)
		return nil
	}
	fmt.Printf("FAILED: %v errors, %v warnings.\n", r.Errors, r.Warnings)
	os.Exit(1)
	return nil
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case audit_verify_command.FullCommand():
			FatalIfError(audit_verify_command, doAuditVerify)
		default:
			return false
		}
		return true
	})
}
