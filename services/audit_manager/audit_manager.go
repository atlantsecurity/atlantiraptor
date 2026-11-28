package audit_manager

import (
	"context"

	"github.com/Velocidex/ordereddict"
	"github.com/sirupsen/logrus"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/paths/artifacts"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/auditlog"
	"www.velocidex.com/golang/velociraptor/utils"
)

type AuditManager struct{}

func (self *AuditManager) LogAudit(
	ctx context.Context,
	config_obj *config_proto.Config,
	principal, operation string,
	details *ordereddict.Dict) error {

	record := ordereddict.NewDict().
		Set("operation", operation).
		Set("principal", principal).
		Set("details", details)

	logger := logging.GetLogger(config_obj, &logging.Audit)
	logger.WithFields(logrus.Fields(record.ToMap())).Info(operation)

	// Only forward the event if running on the server.
	if utils.RunningOnClient(config_obj) {
		return nil
	}

	// The tamper-evident copy on local disk (see services/auditlog).
	// It must not be skipped because the journal fails, and vice versa.
	file_err := auditlog.Record(config_obj.OrgId, principal, operation, details)

	journal, err := services.GetJournal(config_obj)
	if err != nil {
		if file_err != nil {
			return file_err
		}
		return err
	}

	// If an event is important enough to be audit logged we need to
	// make sure to write it synchronously.
	err = journal.PushRowsToArtifact(
		ctx, config_obj, []*ordereddict.Dict{record},
		artifacts.AUDIT_LOGS.
			WithSuperUser().WithFrom(principal))
	if err != nil {
		return err
	}
	return file_err
}
