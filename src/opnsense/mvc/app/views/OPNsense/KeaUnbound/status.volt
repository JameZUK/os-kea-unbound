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
            $("#st_suffix").text(data.qualifying_suffix && data.qualifying_suffix.length
                ? data.qualifying_suffix : "(firewall domain)");
            var owned = data.kea_ddns_managed === "1" ? " (managed by this plugin)" : " (pre-existing)";
            $("#st_kea_ddns").html(fmtBool(data.kea_ddns_enabled === "1") +
                ' <small class="text-muted">' + owned + '</small>');
            $("#st_log").text((data.recent_log || []).join("\n"));
        });
    }
    $(document).ready(function () {
        refreshStatus();
        setInterval(refreshStatus, 5000);
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
    <button class="btn btn-primary" id="syncAct" type="button">
        <b>{{ lang._('Sync now') }}</b> <i id="syncAct_progress"></i>
    </button>
    <span class="text-muted" style="margin-left:1em;">
        {{ lang._('Re-seed existing Kea leases and reservations into Unbound.') }}
    </span>
</div>

<div class="content-box" style="margin-top:1em; padding:1em;">
    <strong>{{ lang._('Recent activity') }}</strong>
    <pre id="st_log" style="margin-top:0.5em; max-height:320px; overflow:auto;">-</pre>
</div>
