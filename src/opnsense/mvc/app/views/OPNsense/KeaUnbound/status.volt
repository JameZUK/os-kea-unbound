{#
 # Copyright (c) 2026 James (JameZUK) - BSD-2-Clause
 #}

<script>
    function fmtBool(v) {
        return v ? '<span class="text-success"><i class="fa fa-check"></i> yes</span>'
                 : '<span class="text-danger"><i class="fa fa-times"></i> no</span>';
    }
    function refreshStatus() {
        ajaxGet("/api/keaunbound/status/get", {}, function (data, status) {
            if (!data || data.status === 'failed') { return; }
            $("#st_enabled").html(fmtBool(data.enabled === "1"));
            $("#st_listener").html(fmtBool(data.listener_running === true));
            $("#st_port").text(data.listener_port || "");
            $("#st_records").text(data.records);
            $("#st_tsig").text(data.tsig);
            var suffix = data.qualifying_suffix
                ? $("<div>").text(data.qualifying_suffix).html() : "-";
            if (data.qualifying_suffix_is_default && data.qualifying_suffix) {
                suffix += ' <small class="text-muted">(' +
                    "{{ lang._('firewall domain') }}" + ')</small>';
            }
            $("#st_suffix").html(suffix);
            var owned = data.kea_ddns_managed === "1" ? " (managed by this plugin)" : " (pre-existing)";
            $("#st_kea_ddns").html(fmtBool(data.kea_ddns_enabled === "1") +
                ' <small class="text-muted">' + owned + '</small>');
        });
    }

    var logCount = 200;             // lines currently requested
    var logStep = 500;             // how many more "Load more" pulls
    var logMax = 20000;            // hard cap (matches backend)
    function refreshLog() {
        // Use a POST (ajaxCall), the same path every OPNsense grid uses — works
        // consistently across browsers and is never cached (a GET here loaded
        // empty under Firefox).
        ajaxCall("/api/keaunbound/status/log", {count: logCount}, function (data, status) {
            if (!data || data.status === 'failed') { return; }
            var lines = data.lines || [];
            var el = document.getElementById("st_log");
            // keep the view pinned to the bottom (live tail) only if the user is
            // already there — don't yank them down while reading older lines.
            var atBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 40;
            // The API HTML-escapes its string output (& < > " ' arrive as entities),
            // which would otherwise show literally (e.g. "injection -&gt;"). Reverse
            // htmlspecialchars explicitly — &amp; LAST so "&amp;gt;" can't double-decode
            // — then render via .text() (textContent), which is XSS-safe regardless.
            var raw = lines.length ? lines.join("\n") : "(no activity logged yet)";
            var decoded = raw.replace(/&lt;/g, "<").replace(/&gt;/g, ">")
                             .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
                             .replace(/&amp;/g, "&");
            $(el).text(decoded);
            if (atBottom) { el.scrollTop = el.scrollHeight; }
            $("#st_log_info").text(lines.length + " line" + (lines.length === 1 ? "" : "s") +
                " shown" + (data.more ? " — more available" : ""));
            $("#logMore").prop("disabled", !data.more || logCount >= logMax);
        });
    }
    $(document).ready(function () {
        refreshStatus();
        refreshLog();
        setInterval(function () { refreshStatus(); refreshLog(); }, 5000);
        $("#logMore").click(function () {
            logCount = Math.min(logCount + logStep, logMax);
            refreshLog();
        });
        $("#syncAct").click(function () {
            $("#syncAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall("/api/keaunbound/service/sync", {}, function (data, status) {
                $("#syncAct_progress").removeClass("fa fa-spinner fa-pulse");
                refreshStatus();
            });
        });
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    <table class="table table-striped">
        <colgroup><col style="width:34%"/><col/></colgroup>
        <tbody>
            <tr><td>{{ lang._('Plugin enabled') }}</td><td id="st_enabled">-</td></tr>
            <tr><td>{{ lang._('DDNS listener running') }}</td><td id="st_listener">-</td></tr>
            <tr><td>{{ lang._('Listener port') }}</td><td id="st_port">-</td></tr>
            <tr><td>{{ lang._('Registered DNS records') }}</td><td id="st_records">-</td></tr>
            <tr><td>{{ lang._('TSIG') }}</td><td id="st_tsig">-</td></tr>
            <tr><td>{{ lang._('Qualifying suffix') }}</td><td id="st_suffix">-</td></tr>
            <tr><td>{{ lang._('Kea DDNS daemon') }}</td><td id="st_kea_ddns">-</td></tr>
        </tbody>
    </table>
    <div style="padding: 0.5em 8px 0;">
        <button class="btn btn-primary" id="syncAct" type="button">
            <b>{{ lang._('Sync now') }}</b> <i id="syncAct_progress"></i>
        </button>
        <span class="text-muted" style="margin-left:1em;">
            {{ lang._('Re-seed existing Kea leases and reservations into Unbound.') }}
        </span>
    </div>
</div>

<div class="content-box" style="margin-top:1em; padding:1em;">
    <strong>{{ lang._('Recent activity') }}</strong>
    <span id="st_log_info" class="text-muted" style="margin-left:0.5em;"></span>
    <pre id="st_log" style="margin-top:0.5em; max-height:300px; overflow-y:auto; overflow-x:hidden; white-space:pre-wrap; overflow-wrap:anywhere;">-</pre>
    <div style="margin-top:0.5em;">
        <button class="btn btn-default btn-xs" id="logMore" type="button">
            <i class="fa fa-angle-double-up"></i> {{ lang._('Load more') }}
        </button>
        <span class="text-muted" style="margin-left:0.5em;">
            {{ lang._('Loads older entries, including rotated log archives.') }}
        </span>
    </div>
</div>
