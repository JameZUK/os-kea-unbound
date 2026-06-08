{#
 # Copyright (c) 2026 James (JameZUK) - BSD-2-Clause
 #}

<script>
    $(document).ready(function () {
        $("#grid-records").UIBootgrid({
            search: '/api/keaunbound/records/search',
            options: {
                selection: false,
                multiSelect: false,
                rowCount: [20, 50, 100, 200, -1],
                formatters: {
                    "scope": function (column, row) {
                        var cls = row.scope === 'reverse' ? 'label-default' : 'label-info';
                        return '<span class="label ' + cls + '">' + row.scope + '</span>';
                    },
                    "expires": function (column, row) {
                        if (!row.expires || row.expires == 0) {
                            return '<span class="text-muted">—</span>';
                        }
                        var d = new Date(row.expires * 1000);
                        return d.toLocaleString();
                    }
                }
            }
        });
    });
</script>

<div class="content-box" style="padding: 1em;">
    <p class="text-muted" style="margin-bottom: 1em;">
        {{ lang._('Dynamic DNS records this plugin has registered in Unbound, enriched with matching Kea lease / reservation detail. Use the search box to filter; click a column header to sort.') }}
    </p>
    <table id="grid-records" class="table table-condensed table-hover table-striped"
           data-store-selection="false">
        <thead>
            <tr>
                <th data-column-id="name" data-sortable="true">{{ lang._('Name') }}</th>
                <th data-column-id="type" data-sortable="true" data-width="5em">{{ lang._('Type') }}</th>
                <th data-column-id="scope" data-sortable="true" data-width="8em" data-formatter="scope">{{ lang._('Scope') }}</th>
                <th data-column-id="value" data-sortable="true">{{ lang._('Data') }}</th>
                <th data-column-id="hostname" data-sortable="true">{{ lang._('Hostname') }}</th>
                <th data-column-id="hwaddr" data-sortable="true">{{ lang._('MAC / DUID') }}</th>
                <th data-column-id="subnet" data-sortable="true" data-width="6em">{{ lang._('Subnet') }}</th>
                <th data-column-id="source" data-sortable="true" data-width="8em">{{ lang._('Source') }}</th>
                <th data-column-id="expires" data-sortable="true" data-formatter="expires">{{ lang._('Expires') }}</th>
                <th data-column-id="ttl" data-sortable="true" data-type="numeric" data-width="5em">{{ lang._('TTL') }}</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>
