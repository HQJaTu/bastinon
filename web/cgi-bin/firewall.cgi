#!/usr/bin/perl -w --

use utf8;
use strict;
use warnings;

use CGI::Carp qw(fatalsToBrowser);
use Mojolicious::Lite;
use Mojo::HTTPStatus qw(OK MOVED_PERMANENTLY FOUND SEE_OTHER FORBIDDEN NOT_FOUND NOT_ACCEPTABLE);
use Mojo::JSON qw(decode_json encode_json);
use Net::DBus;

use constant FIREWALL_UPDATER_SERVICE_BUS_NAME => "fi.hqcodeshop.Firewall";


sub _get_dbus() {
    # Helper:
    # Docs: https://metacpan.org/pod/Net::DBus
    my $bus = Net::DBus->system();

    # Get a handle to the Firewall updater service
    my $proxy = $bus->get_service(FIREWALL_UPDATER_SERVICE_BUS_NAME);
    # Get the device manager
    my $manager = $proxy->get_object('/' . FIREWALL_UPDATER_SERVICE_BUS_NAME =~ s:\.:/:gr,
        FIREWALL_UPDATER_SERVICE_BUS_NAME);

    return $manager;
}

get '/' => sub {
    my ($c) = @_;

    my $requesting_user = $c->req->env->{REMOTE_USER};
    if (!$requesting_user) {
        $c->render(text => "Need user!", status => FORBIDDEN);
    }
    my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwnam($requesting_user);
    my ($user_name, $_) = split(/,/, $gcos, 2); # Assume first comma-separated field of GECOS is user's full name.
    $c->stash(
        name     => $name . " / " . $user_name,
        base_url => $c->req->url
    );
    $c->render(template => 'index');
};

get '/api/services' => sub {
    my ($c) = @_;

    my $manager = _get_dbus();
    my @services = @{$manager->GetServices()};

    # Return
    my $json = {
        "services" => [ @services ]
    };
    $c->render(json => $json, status => OK);
};

get '/api/protocols' => sub {
    my ($c) = @_;

    my $manager = _get_dbus();
    my @protocols = @{$manager->GetProtocols()};

    # Return
    my $json = {
        "protocols" => [ @protocols ]
    };
    $c->render(json => $json, status => OK);
};

get '/api/rules' => sub {
    my ($c) = @_;

    my $manager = _get_dbus();
    my $user = getpwuid($<);
    my @rules = @{$manager->GetRules($user)};

    # Return
    my $json = {
        "user"  => $user,
        "rules" => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

put '/api/rules/:id' => sub {
    # Docs: https://restfulapi.net/rest-put-vs-post/
    my ($c) = @_;

    my $rule_id = $c->param('id');
    my $body_json = decode_json($c->req->body);
    my $manager = _get_dbus();
    my $user = getpwuid($<);
    my $new_rule_id = $manager->UpsertRule(
        $rule_id,
        $user,
        $body_json->{'service'},
        $body_json->{'source'},
        $body_json->{'comment'},
        $body_json->{'expiry'}
    );

    my @rules = @{$manager->GetRules($user)};

    # Return
    my $json = {
        "user"  => $user,
        "rule_id" => $new_rule_id,
        "rules" => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

del '/api/rules/:id' => sub {
    # Docs: https://restfulapi.net/rest-put-vs-post/
    my ($c) = @_;

    my $rule_id = $c->param('id');
    my $manager = _get_dbus();
    my $user = getpwuid($<);
    my $new_rule_id = $manager->DeleteRule(
        $rule_id,
        $user
    );

    my @rules = @{$manager->GetRules($user)};

    # Return
    my $json = {
        "user"  => $user,
        "rules" => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

app->start();

__DATA__
@@ index.html.ep
<!DOCTYPE html>
<html lang="en-US">
<head>
<title>Firewall rules</title>
<style>
#rules_table_holder {
    width: 100%;
    min-height: 300px;
    height: auto;
}
#rules_table {
    min-width: 800px;
}
#rules_table th, #rules_table td {
    border: 1px solid;
}
.center_align {
    text-align: center;
}
input[type=number] {
    -moz-appearance: textfield;
    appearance: textfield;
    margin: 0;
}
.source_input {
    width: 200px;
}
.comment_input {
    width: 300px;
}
.expiry_input {
    width: 200px;
}
.effective_column {
}
.action_input {
    width: 150px;
}
</style>
</head>

<body>
<h1>Firewall Rules</h1>
Hello <%= $name %>
<div id="rules_table_holder">
    <h2>... Loading rules ...</h2>
</div>
<br/>
<div id="buttons">
    <button id="reload_rules">Reload rules from server discarding any possible changes</button>
</div>
<script src="../jquery-3.6.0.min.js"></script>
<script>
let bastinon_services = null;
let bastinon_rules = null;

$(document).ready(() => {
    console.log( `ready! <%= $base_url %>` );

    // Get rules:
    load_rules(true);

    // Get all available firewall services:
    $.ajax({
        url: `${window.location.href}/api/services`,
        method: 'get',
        context: document.body
    }).done((data) => {
        console.log("ready(): got services");
        bastinon_services = data['services'];

        update_rules();
    });

    // Refresh-button:
    $("#reload_rules").click(() => {
        load_rules(true);
    });
});

load_rules = (update_ui) => {
    // Docs: https://api.jquery.com/jquery.ajax/
    $.ajax({
        url: `${window.location.href}/api/rules`,
        method: 'get',
        context: document.body
    }).done((data) => {
        console.log("load_rules(): got rules");
        bastinon_rules = data['rules'];

        if (update_ui) {
            update_rules();
        }
    });
}

update_rules = () => {
    if (!bastinon_rules || !bastinon_services) {
        // XXX Debug:
        //console.log(`Fail! Missing data at this point.`);
        return;
    }

    const table_div = $('#rules_table_holder');
    let update_button_ids = [];

    // Iterate all rules
    let html = '';
    for (const rule of bastinon_rules) {
        const rule_id = rule[0];
        const rule_effective = rule[6] ? "Active" : "inactive";
        let service_opts = '';
        for (const service of bastinon_services) {
            if (service[0] === rule[2]) {
                service_opts += `<option value="${service[0]}" selected>${service[1]}</option>`;
            } else {
                service_opts += `<option value="${service[0]}">${service[1]}</option>`;;
            }
        }

        // Go for HTML:
        html += `<tr>
  <td><select id="service_${rule_id}" class="service_input">${service_opts}</select></td>
  <td><input type="text" id="source_${rule_id}" required value="${rule[3]}" class="source_input"></td>
  <td><input type="text" id="comment_${rule_id}" value="${rule[4]}" class="comment_input"></td>
  <td><input type="datetime-local" id="expiry_${rule_id}" value="${rule[5]}" class="expiry_input"></td>
  <td class="effective_column">${rule_effective}</td>
  <td class="center_align" class="action_input">
    <button id="update_rule_btn_${rule_id}">Update</button>
    <button id="delete_rule_btn_${rule_id}">Delete</button>
  </td>
</tr>`;

        // Update-button:
        update_button_ids.push(rule_id)
    }

    // Add new row to bottom
    const rule_id = "new";
    let service_opts = '<option value="">-Select-</option>';
    for (const service of bastinon_services) {
        service_opts += `<option value="${service[0]}">${service[1]}</option>`;
    }
    html += `<tr>
  <td><select id="service_${rule_id}" class="service_input">${service_opts}</select></td>
  <td><input type="text" id="source_${rule_id}" required class="source_input"></td>
  <td><input type="text" id="comment_${rule_id}" class="comment_input"></td>
  <td><input type="datetime-local" id="expiry_${rule_id}" class="expiry_input"></td>
  <td class="effective_column">new</td>
  <td class="center_align" class="action_input">
    <button id="add_rule_btn">Add</button>
  </td>
</tr>`;

    // Re-do the <div/>-contents with a freshly created table
    table_div.html(`<table id="rules_table">
<tr>
    <th>Service</th>
    <th>Source address</th>
    <th>Comment</th>
    <th>Expiry (UTC)</th>
    <th>Rule active</th>
    <th>Action</th>
</tr>
${html}
</table>`);

    // Buttons:
    for (const rule_id of update_button_ids) {
        const update_button_id = `update_rule_btn_${rule_id}`;
        const delete_button_id = `delete_rule_btn_${rule_id}`;
        $(`#${update_button_id}`).click(() => {
            // XXX Debug:
            //console.log(`Update button "${rule_id}" clicked!`);
            const service = $(`#service_${rule_id}`).val();
            const source = $(`#source_${rule_id}`).val();
            const comment = $(`#comment_${rule_id}`).val();
            let expiry = $(`#expiry_${rule_id}`).val();
            if (expiry && !expiry.match(/T\d{2}:\d{2}:\d{2}$/)) {
                expiry += ':00';
            }
            upsert_rule(rule_id, service, source, comment, expiry)
        });
        $(`#${delete_button_id}`).click(() => {
            // XXX Debug:
            //console.log(`Delete button "${rule_id}" clicked!`);
            const service = $(`#service_${rule_id}`).val();
            const source = $(`#source_${rule_id}`).val();
            const confirm_message = `Really want to delete ${service} rule allowing ${source}?`;
            if (confirm(confirm_message)) {
                delete_rule(rule_id)
            }
        });
    }
}

upsert_rule = (rule_id, service, source, comment, expiry) => {
    $.ajax({
        url: `${window.location.href}/api/rules/${rule_id}`,
        method: 'put',
        context: document.body,
        data: JSON.stringify({
            'service': service,
            'source': source,
            'comment': comment,
            'expiry': expiry
        }),
        dataType: "json",
        contentType : 'application/json',
        processData : false
    }).done((data) => {
        console.log(`ok, upsert rule ${rule_id} ok`);
        bastinon_rules = data['rules'];

        update_rules();
    });
}

delete_rule = (rule_id) => {
    $.ajax({
        url: `${window.location.href}/api/rules/${rule_id}`,
        method: 'delete',
        context: document.body
    }).done((data) => {
        console.log(`ok, delete rule ${rule_id} ok`);
        bastinon_rules = data['rules'];

        update_rules();
    });
}

// end JavaScript
</script>
</body>
</html>