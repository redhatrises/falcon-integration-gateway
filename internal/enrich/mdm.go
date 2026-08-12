package enrich

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
)

// RTR command strings that extract the per-OS MDM identifier. They match the
// legacy gateway byte-for-byte so downstream identifiers stay stable: Windows
// reads the OMADM device-client id from the registry (a non-admin read);
// macOS runs system_profiler to pull the hardware UUID (an admin runscript).
const (
	winMDMCommand = `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" DeviceClientId`
	macMDMCommand = "runscript -Raw=```system_profiler SPHardwareDataType | awk '/UUID/ { print $3; }'```"
)

// MDMIdentifier resolves the device-management identifier for a sensor by
// running a per-OS Real Time Response command. Only Windows and macOS carry an
// MDM identifier; any other platform resolves to an empty string with no
// session opened. The RTR session is always closed once the lookup returns.
func (e *Resolver) MDMIdentifier(ctx context.Context, sensorID, platform string) (string, error) {
	if id, ok := e.mdmCache.Get(sensorID); ok {
		return id, nil
	}

	var (
		baseCommand string
		commandLine string
		admin       bool
		parse       func(string) string
	)
	switch platform {
	case "Windows":
		baseCommand, commandLine, admin, parse = "reg query", winMDMCommand, false, parseWindowsMDM
	case "Mac":
		baseCommand, commandLine, admin, parse = "runscript", macMDMCommand, true, parseMacMDM
	default:
		return "", nil
	}

	v, err, _ := e.mdmGroup.Do(sensorID, func() (any, error) {
		// A concurrent caller may have populated the cache while this flight was
		// queued; re-check before opening a session.
		if id, ok := e.mdmCache.Get(sensorID); ok {
			return id, nil
		}

		status, err := e.runRTRCommand(ctx, sensorID, client.RTRCommand{
			BaseCommand:   baseCommand,
			CommandString: commandLine,
			Admin:         admin,
		})
		if err != nil {
			return "", err
		}

		// A command that wrote to stderr produced no usable identifier; treat it
		// as "no MDM identifier" and cache that so a later event does not re-run
		// RTR.
		var id string
		if status.Stderr == "" {
			id = parse(status.Stdout)
		}
		e.mdmCache.Add(sensorID, id)
		return id, nil
	})
	if err != nil {
		return "", err
	}
	id, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("enrich: unexpected MDM result type %T", v)
	}
	return id, nil
}

// parseWindowsMDM extracts the MDM identifier from `reg query` output. It mirrors
// the legacy parse: take everything after the first " = " separator, then the
// first line of that remainder. Output without a separator yields "".
func parseWindowsMDM(stdout string) string {
	_, after, found := strings.Cut(stdout, " = ")
	if !found {
		return ""
	}
	line, _, _ := strings.Cut(after, "\n")
	return line
}

// parseMacMDM extracts the hardware UUID from system_profiler output: the first
// line of stdout.
func parseMacMDM(stdout string) string {
	line, _, _ := strings.Cut(stdout, "\n")
	return line
}
