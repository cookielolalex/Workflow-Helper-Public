# Windows capture agent

This project is the Windows-native edge of the vertical slice. It detects an
allowlisted foreground AutoCAD process and creates a versioned session package.

## Safety gate

The service does nothing unless both `CaptureEnabled` and
`ConsentAcknowledged` are `true`. The recorder registered in this checkpoint is
`DisabledCaptureRecorder`; it creates no video. Replace it only after the pilot
privacy review and add a visible recording indicator and pause control at the
same time.

## Development

On Windows with .NET 8:

```powershell
dotnet restore
dotnet run
```

Use only synthetic test drawings. Set a company-issued pseudonymous machine ID
in local configuration and never commit that value.

## Production work still required

- signed installer and service recovery policy
- device enrollment and authentication
- user-visible status/pause control
- approved-window recording implementation
- AutoCAD supported API plug-in for command/drawing events
- DWG-safe before/after snapshot strategy
- resumable upload, server verification, and local deletion policy
- tamper-aware audit events and operational monitoring
