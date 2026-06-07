{#
 # Copyright (c) 2026 James (JameZUK) - BSD-2-Clause
 #}

<script>
    $(document).ready(function() {
        var data_get_map = {'frm_general': "/api/keaunbound/general/get"};
        mapDataToFormUI(data_get_map).done(function(data) {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        // Save
        $("#saveAct").click(function() {
            saveFormToEndpoint("/api/keaunbound/general/set", 'frm_general', function() {
                $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall("/api/keaunbound/service/reconfigure", {}, function(data, status) {
                    $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    <div class="col-md-12">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i>
        </button>
    </div>
</div>
