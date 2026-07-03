import { PoP } from "../../../../types/pop.types.js";
import sudoPrompt from "sudo-prompt";

export default class Firewall {
    async runAsAdmin(
        cmd: string,
    ): Promise<{ stdout: string | Buffer<ArrayBufferLike>; stderr: string | Buffer<ArrayBufferLike> }> {
        return new Promise((resolve, reject) => {
            sudoPrompt.exec(cmd, { name: "CS2 Server Picker" }, (error, stdout, stderr) => {
                if (error) {
                    reject({ stdout: stdout ?? "", stderr: error.message });
                } else {
                    resolve({ stdout: stdout ?? "", stderr: stderr ?? "" });
                }
            });
        });
    }

    createBlockRuleCmd({ ips, dir, proto }: { ips: string[]; dir: "in" | "out"; proto: "TCP" | "UDP" }): {
        ruleName: string;
        cmd: string;
    } {
        const ruleName = `CS2_MM_SERVER_PICKER_${dir}_${proto}`;
        const ipsetName = ruleName.replace(/[^A-Za-z0-9_]/g, "_"); // ensure valid ipset name

        // Compose commands using ipset + iptables. ipset is efficient for many IPs.
        const cmds: string[] = [];

        // create ipset (ignore error if exists)
        cmds.push(`ipset create ${ipsetName} hash:ip -exist`);

        // add each ip to the set
        for (const ip of ips) {
            cmds.push(`ipset add ${ipsetName} ${ip} -exist`);
        }

        // insert iptables rule referencing the set
        const tableChain = dir === "in" ? "INPUT" : "OUTPUT";
        const matchDir = dir === "in" ? "src" : "dst";
        const protocol = proto.toLowerCase();

        cmds.push(
            `iptables -I ${tableChain} -m set --match-set ${ipsetName} ${matchDir} -p ${protocol} -j DROP -m comment --comment '${ruleName}'`
        );

        const cmd = cmds.join(" && ");

        return {
            ruleName,
            cmd,
        };
    }

    createUnblockRuleCmd(ruleName: string): string {
        const ipsetName = ruleName.replace(/[^A-Za-z0-9_]/g, "_");

        const cmds: string[] = [];

        // Delete iptables rules for both INPUT/OUTPUT and TCP/UDP. Use || true to ignore not-found errors
        cmds.push(`iptables -D INPUT -m set --match-set ${ipsetName} src -p udp -j DROP -m comment --comment '${ruleName}' || true`);
        cmds.push(`iptables -D INPUT -m set --match-set ${ipsetName} src -p tcp -j DROP -m comment --comment '${ruleName}' || true`);
        cmds.push(`iptables -D OUTPUT -m set --match-set ${ipsetName} dst -p udp -j DROP -m comment --comment '${ruleName}' || true`);
        cmds.push(`iptables -D OUTPUT -m set --match-set ${ipsetName} dst -p tcp -j DROP -m comment --comment '${ruleName}' || true`);

        // destroy the ipset (ignore error if not exists)
        cmds.push(`ipset destroy ${ipsetName} || true`);

        return cmds.join(" && ");
    }

    async blockPops(pops: PoP[]): Promise<
        {
            ruleName: string;
            status: string;
            stderr: string | Buffer<ArrayBufferLike>;
            stdout: string | Buffer<ArrayBufferLike>;
        }[]
    > {
        const ips = pops.flatMap((pop) => pop.relays.map((relay) => relay.ipv4));

        // If running on Windows, keep original powershell/netsh behavior
        if (process.platform === "win32") {
            // Reuse existing netsh approach for Windows
            const ruleCommands = [] as { ruleName: string; cmd: string }[];

            const ruleNamesAndCmds = [
                { dir: "in", proto: "UDP" },
                { dir: "in", proto: "TCP" },
                { dir: "out", proto: "UDP" },
                { dir: "out", proto: "TCP" },
            ];

            for (const r of ruleNamesAndCmds) {
                const ruleName = `CS2_MM_SERVER_PICKER_${r.dir}_${r.proto}`;
                const remoteIps = ips.join(",");
                const cmd = [
                    `netsh advfirewall firewall add rule`,
                    `name="${ruleName}"`,
                    `dir=${r.dir}`,
                    `action=block`,
                    `protocol=${r.proto}`,
                    `remoteip=${remoteIps}`,
                    `profile=domain,private,public`,
                ].join(" ");
                ruleCommands.push({ ruleName, cmd });
            }

            const cmdScript = ruleCommands.map((c) => c.cmd).join(" && ");

            const { stdout, stderr } = await this.runAsAdmin(`powershell -Command ${cmdScript}`);

            return ruleCommands.map(({ ruleName }) => ({
                ruleName,
                status: stderr ? "error" : "success",
                stderr,
                stdout,
            }));
        }

        // For Linux (Arch), use ipset + iptables approach
        const commands = [
            this.createBlockRuleCmd({ ips, dir: "in", proto: "UDP" }),
            this.createBlockRuleCmd({ ips, dir: "in", proto: "TCP" }),
            this.createBlockRuleCmd({ ips, dir: "out", proto: "UDP" }),
            this.createBlockRuleCmd({ ips, dir: "out", proto: "TCP" }),
        ];

        const cmdScript = commands.map((c) => c.cmd).join(" && ");

        // Run via /bin/sh -c to ensure compound commands work as expected
        const safeCmd = cmdScript.replace(/"/g, '\\"');
        const { stdout, stderr } = await this.runAsAdmin(`/bin/sh -c "${safeCmd}"`);

        return commands.map(({ ruleName }) => ({
            ruleName,
            status: stderr ? "error" : "success",
            stderr,
            stdout,
        }));
    }

    async unblockPops(ruleNames: string[]): Promise<
        {
            ruleName: string;
            status: string;
            stderr: string | Buffer<ArrayBufferLike>;
            stdout: string | Buffer<ArrayBufferLike>;
        }[]
    > {
        // Windows removal using powershell/netsh if on Windows
        if (process.platform === "win32") {
            const commands = ruleNames.map((ruleName) => `netsh advfirewall firewall delete rule name="${ruleName}"`).join(" && ");

            const { stdout, stderr } = await this.runAsAdmin(`powershell -Command ${commands}`);

            return ruleNames.map((ruleName) => ({
                ruleName,
                status: stderr ? "error" : "success",
                stderr,
                stdout,
            }));
        }

        // For Linux: remove iptables rules and destroy ipset
        const commands = ruleNames.map((ruleName) => this.createUnblockRuleCmd(ruleName)).join(" && ");

        const safeCmd = commands.replace(/"/g, '\\"');
        const { stdout, stderr } = await this.runAsAdmin(`/bin/sh -c "${safeCmd}"`);

        return ruleNames.map((ruleName) => ({
            ruleName,
            status: stderr ? "error" : "success",
            stderr,
            stdout,
        }));
    }
}
