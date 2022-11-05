#!/usr/bin/perl -wT --

use utf8;
use strict;
use warnings;

use CGI::Carp qw(fatalsToBrowser);
use open ':encoding(UTF-8)'; # Default encoding of file handles.
use Mojolicious::Lite;
use Mojo::HTTPStatus qw(OK MOVED_PERMANENTLY FOUND SEE_OTHER FORBIDDEN NOT_FOUND NOT_ACCEPTABLE);
use Mojo::JSON qw(decode_json encode_json);
use Net::DBus;
use Net::Whois::IP qw(whoisip_query);
use Data::Validate::IP qw(is_ipv4 is_ipv6 is_public_ip);
use NetAddr::IP;
use Encode;

use constant VERSION => '0.9';
use constant FIREWALL_UPDATER_SERVICE_BUS_NAME => "fi.hqcodeshop.Bastinon";


sub _get_dbus() {
    # Helper:
    # Docs: https://metacpan.org/pod/Net::DBus
    my $bus = Net::DBus->system();

    # Get a handle to the Firewall updater service
    my $proxy = $bus->get_service(FIREWALL_UPDATER_SERVICE_BUS_NAME);
    # Get the device manager
    my $object_path = '/' . FIREWALL_UPDATER_SERVICE_BUS_NAME =~ s:\.:/:gr;
    my $interface = FIREWALL_UPDATER_SERVICE_BUS_NAME;
    my $manager = $proxy->get_object($object_path, $interface);

    return $manager;
}

sub _post_process_rules(\@$) {
    my ($rules_ref, $remote_ip) = @_;

    my $remote_ip_family = 0;
    my $remote_ip_object;
    if ($remote_ip) {
        $remote_ip_family = is_ipv4($remote_ip) ? 4 : is_ipv6($remote_ip) ? 6 : 0;
        $remote_ip_object = NetAddr::IP->new($remote_ip);
    }
    # Post-process:
    # D-Bus uses internally only UTF-8. Characters arriving into Perl won't be correctly decoded.
    # Do the decoding here. Iterating dbus_array() is tricky! It doesn't behave like regular Perl array.
    for my $rule_idx (0 .. $#{$rules_ref}) {
        # Do some source matching
        my $source = $rules_ref->[$rule_idx][3];
        my $source_space = NetAddr::IP->new($source);
        # As source and source_space can be a network, we MUST provide is_ipv4() an address.
        my $source_ip_family = is_ipv4($source_space->addr) ? 4 : is_ipv6($source_space->addr) ? 6 : 0;
        my $source_match = 0;
        if ($remote_ip_family == 4 && $source_ip_family == 4) {
            if ($source_space->contains($remote_ip_object)) {
                $source_match = 1;
            }
        }
        elsif ($remote_ip_family == 6 && $source_ip_family == 6) {
            if ($source_space->contains($remote_ip_object)) {
                $source_match = 1;
            }
        }
        push(@{$rules_ref->[$rule_idx]}, $source_match);

        # Process comment (if any)
        my $comment = $rules_ref->[$rule_idx][4];
        next if (!$comment);

        $rules_ref->[$rule_idx][4] = Encode::decode("UTF-8", $comment);
    }
}

get '/' => sub {
    my ($c) = @_;

    my $requesting_user = $c->req->env->{REMOTE_USER};
    if (!$requesting_user) {
        $c->render(text => "Need user!", status => FORBIDDEN);
    }
    my ($name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir, $shell, $expire) = getpwnam($requesting_user);
    my ($user_name, $_) = split(/,/, $gcos, 2); # Assume first comma-separated field of GECOS is user's full name.
    my $remote_ip = $c->tx->remote_address;
    my $remote_ip_family = is_ipv4($remote_ip) ? 4 : is_ipv6($remote_ip) ? 6 : 0;
    my $remote_ip_is_public = is_public_ip($remote_ip);

    # Data to be stashed for later use in HTML-template:
    $c->stash(
        name                 => $name . " / " . $user_name,
        base_url             => $c->req->url,
        remote_ip            => $remote_ip,
        remote_ip_family     => $remote_ip_family,
        remote_ip_is_public  => $remote_ip_is_public ? 1 : 0,
        remote_ip_public_str => $remote_ip_is_public ? "Public IPv" . $remote_ip_family : "non-public IPv" . $remote_ip_family,
        version              => VERSION
    );
    $c->render(template => 'index');
};

get '/api/remote/network' => sub {
    my ($c) = @_;

    my $remote_ip = $c->tx->remote_address;
    my $remote_ip_is_public = is_public_ip($remote_ip);
    my $success = \0; # Perl JSON -trickery, will convert 0 to False and 1 to True
    my $remote_network = undef;
    my $remote_org_name = undef;
    if ($remote_ip_is_public) {
        app->log->debug(sprintf("Remote IP %s public, querying", $remote_ip));
        # Net::Whois::IP::whois_servers contains list of sources
        my ($response, $array_of_responses) = whoisip_query($remote_ip, 'RIPE', 0); # Do not search multiple servers

        $remote_ip_is_public = \1;
        $success = \1;
        $remote_network = $response->{'route'};
        $remote_org_name = $response->{'org-name'};
        $remote_org_name = $response->{'netname'} if (!$remote_org_name);
    }
    else {
        $remote_ip_is_public = \0;
        app->log->debug(sprintf("Remote IP %s not public", $remote_ip));
    }

    # Return
    my $json = {
        remote_ip_is_public => $remote_ip_is_public,
        remote_ip           => $remote_ip,
        query_done          => $success,
        remote_network      => $remote_network,
        remote_org_name     => $remote_org_name
    };
    $c->render(json => $json, status => OK);
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
    my $remote_ip = $c->tx->remote_address;
    _post_process_rules(@rules, $remote_ip);

    # Return
    my $json = {
        "user"  => $user,
        "rules" => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

post '/api/rules/' => sub {
    my ($c) = @_;

    return _post_or_put(@_);
};
put '/api/rules/:id' => sub {
    my ($c) = @_;

    return _post_or_put(@_);
};

sub _post_or_put {
    # Docs: https://restfulapi.net/rest-put-vs-post/
    my ($c) = @_;

    my $remote_ip = $c->tx->remote_address;
    my $rule_id = $c->param('id');
    my $body_json = decode_json($c->req->body);
    my $manager = _get_dbus();
    my $user = getpwuid($<);
    my $new_rule_id = undef;
    eval {
        $new_rule_id = $manager->UpsertRule(
            $rule_id,
            $user,
            $body_json->{'service'},
            $body_json->{'source'},
            $body_json->{'comment'},
            $body_json->{'expiry'}
        );
    } or do {
        my $e = $@;

        if ($e =~ /\s+(\S+Error): ([^\n]+)$/s) {
            # Parse Python error
            $e = "$1: $2"
        }

        # Return error
        my $json = {
            "user"  => $user,
            "error" => $e
        };
        $c->render(json => $json, status => NOT_ACCEPTABLE);

        return;
    };

    my @rules = @{$manager->GetRules($user)};
    _post_process_rules(@rules, $remote_ip);

    # Return
    my $json = {
        "user"    => $user,
        "rule_id" => $new_rule_id,
        "rules"   => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

del '/api/rules/:id' => sub {
    # Docs: https://restfulapi.net/rest-put-vs-post/
    my ($c) = @_;

    my $remote_ip = $c->tx->remote_address;
    my $rule_id = $c->param('id');
    my $manager = _get_dbus();
    my $user = getpwuid($<);
    my $new_rule_id = $manager->DeleteRule(
        $rule_id,
        $user
    );

    my @rules = @{$manager->GetRules($user)};
    _post_process_rules(@rules, $remote_ip);

    # Return
    my $json = {
        "user"  => $user,
        "rules" => [ @rules ]
    };
    $c->render(json => $json, status => OK);
};

get '/api/firewall/status' => sub {
    my ($c) = @_;

    my $manager = _get_dbus();
    my $updates_needed = $manager->FirewallUpdatesNeeded();

    # Return
    # Note: Perl needs bit of JSON-trickery to return boolean values
    my $json = {
        "updates_needed" => $updates_needed ? \1 : \0
    };
    $c->render(json => $json, status => OK);
};

put '/api/firewall/update' => sub {
    my ($c) = @_;

    my $manager = _get_dbus();
    $manager->FirewallUpdate();

    # Return
    my $json = {
        "updated" => \1
    };
    $c->render(json => $json, status => OK);
};

app->secrets([ 'BastiNon is a non-bastion bastion' ]);
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
#user_rules_table, #shared_rules_table {
    min-width: 800px;
}
#user_rules_table th, #user_rules_table td, #shared_rules_table th, #shared_rules_table td {
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
input:required, select:required {
    background-color: #eeeeee;
}
input:invalid, select:invalid {
    background-color: #fd8b8b;
}
.source_input {
    width: 200px;
    font-size: 14pt;
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
.ip-address_display {
    background-color: #f8f8f8;
    width: 200px;
    text-align: left;
    font-size: 18pt;
}
.matching-rule {
    background-color: #a4dfa4;
}
.service_input {
    font-size: 12pt;
}
footer {
    color: #cccccc;
    padding-top: 20px;
}
</style>
</head>

<body>
<h1>Firewall Rules</h1>
<p>Hello <%= $name %></p>
<p>
    Your request originates from:
    <input type="text" value="<%= $remote_ip %>" readonly id="ip-address" class="ip-address_display" />
    &nbsp;[a <%= $remote_ip_public_str %>]<br/>
    <span id="network_info"></span>
</p>
<div id="user_rules_table_holder">
    <h2>... Loading rules ...</h2>
</div>
<br/>
<div id="buttons">
    <button id="reload_rules_btn">Reload rules from server discarding any possible changes</button>
    <button id="rules_into_effect_btn" disabled>Make rules effective</button>
</div>
<div id="common_rules_table_holder">
    <h2>... Loading rules ...</h2>
</div>
<script src="../jquery-3.6.0.min.js"></script>
<script>
let bastinon_services = null;
let bastinon_rules = null;
let bastinon_rule_load_time = null;
const bastinon_rule_expiry_time = 3600; // Seconds
let bastinon_needs_updating = false;

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

    // Query for if network information was possibly available
    network_information();

    // Refresh-button:
    $("#reload_rules_btn").click(() => {
        load_rules(true);
    });

    // Update-button:
    $("#rules_into_effect_btn").click(() => {
        rules_into_effect();
    });
});

$(document).on("visibilitychange", (ev) => {
    //console.log(`Visibility changed: ${document.visibilityState}`);
    if (document.visibilityState === 'visible') {
        if (bastinon_rule_load_time) {
            const last_load_time_diff = new Date(Date.now()) - bastinon_rule_load_time;
            if (last_load_time_diff > bastinon_rule_expiry_time * 1000) {
                load_rules(true);
            }
        }
    }
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
        bastinon_rule_load_time = new Date(Date.now());

        if (update_ui) {
            update_rules();
        }
    });

    query_firewall_status();
}

update_rules = () => {
    if (!bastinon_rules || !bastinon_services) {
        // XXX Debug:
        //console.log(`Fail! Missing data at this point.`);
        return;
    }

    const user_table_div = $('#user_rules_table_holder');
    const common_table_div = $('#common_rules_table_holder');
    let update_button_ids = ["new"];

    // Iterate all rules
    let user_html = '';
    let shared_html = '';
    let service_name = null;
    for (const rule of bastinon_rules) {
        const rule_id = rule[0];
        const rule_effective = rule[6] ? "Active" : "inactive";
        let service_opts = '';
        for (const service of bastinon_services) {
            if (service[0] === rule[2]) {
                service_name = service[1];
                service_opts += `<option value="${service[0]}" selected>${service_name}</option>`;
            } else {
                service_opts += `<option value="${service[0]}">${service[1]}</option>`;;
            }
        }
        const row_class = rule[7] ? "matching-rule" : "non-matching-rule";

        // Go for HTML:
        if (rule[1]) {
            // Has owner! This is user's rule.
            user_html += `<tr class="${row_class}">
  <td>
    <form id="rules_form_${rule_id}">
      <select id="service_${rule_id}" required class="service_input">${service_opts}</select>
    </form>
  </td>
  <td><input type="text" form="rules_form_${rule_id}" id="source_${rule_id}" required class="source_input"></td>
  <td><input type="text" form="rules_form_${rule_id}" id="comment_${rule_id}" class="comment_input"></td>
  <td><input type="datetime-local" form="rules_form_${rule_id}" id="expiry_${rule_id}" class="expiry_input"></td>
  <td class="effective_column">${rule_effective}</td>
  <td class="center_align" class="action_input">
    <button id="update_rule_btn_${rule_id}" form="rules_form_${rule_id}">Update</button>
    <button id="delete_rule_btn_${rule_id}" form="rules_form_${rule_id}">Delete</button>
  </td>
</tr>`;
        } else {
            shared_html += `<tr class="${row_class}">
  <td>${service_name}</td>
  <td>${rule[3]}</td>
  <td>${rule[4]}</td>
  <td>${rule[5]}</td>
  <td class="effective_column">${rule_effective}</td>
</tr>`;
        }

        // Update-button:
        update_button_ids.push(rule_id)
    }

    // Add new row to bottom
    const rule_id = "new";
    let service_opts = '<option value="">-Select-</option>';
    for (const service of bastinon_services) {
        service_opts += `<option value="${service[0]}">${service[1]}</option>`;
    }
    user_html += `<tr>
  <td>
    <form id="rules_form_${rule_id}">
      <select id="service_${rule_id}" required class="service_input">${service_opts}</select>
    </form>
  </td>
  <td><input type="text" form="rules_form_${rule_id}" id="source_${rule_id}" required class="source_input"></td>
  <td><input type="text" form="rules_form_${rule_id}" id="comment_${rule_id}" class="comment_input"></td>
  <td><input type="datetime-local" form="rules_form_${rule_id}" id="expiry_${rule_id}" class="expiry_input"></td>
  <td class="effective_column">new</td>
  <td class="center_align" class="action_input">
    <button id="update_rule_btn_${rule_id}" form="rules_form_${rule_id}">Add</button>
    <button id="fake_new_button_to_prevent_submit_event" style="display: none;" />
  </td>
</tr>`;

    // Re-do the <div/>-contents with a freshly created table
    user_table_div.html(`
<h2>User rules:</h2>
<table id="user_rules_table">
<tr>
    <th>Service</th>
    <th>Source address</th>
    <th>Comment</th>
    <th>Expiry (UTC)</th>
    <th>Rule active</th>
    <th>Action</th>
</tr>
${user_html}
</table>`);
    common_table_div.html(`
<hr/>
<h2>Rules shared by all users:</h2>
<table id="shared_rules_table">
<tr>
    <th>Service</th>
    <th>Source address</th>
    <th>Comment</th>
    <th>Expiry (UTC)</th>
    <th>Rule active</th>
</tr>
${shared_html}
</table>`);

    // Add values to fields as post-process.
    // This way we won't have to escape HTML-entities.
    let source_matched = false;
    for (const rule of bastinon_rules) {
        const rule_id = rule[0];
        const source_field = $(`#source_${rule_id}`);
        const comment_field = $(`#comment_${rule_id}`);
        const expiry_field = $(`#expiry_${rule_id}`);

        source_field.val(rule[3]);
        comment_field.val(rule[4]);
        expiry_field.val(rule[5]);

        if (rule[7])
            source_matched = true;
    }
    // UX-helper:
    // For the new rule -row, add source value if not matched by any rule.
    if (!source_matched) {
        const rule_id = "new";
        const source_field = $(`#source_${rule_id}`);
        const current_ip = $("#ip-address").val();

        source_field.val(current_ip);
    }

    // Event handers for buttons and forms:
    for (const rule_id of update_button_ids) {
        const update_button_id = `update_rule_btn_${rule_id}`;
        const delete_button_id = `delete_rule_btn_${rule_id}`;
        const form_id = `rules_form_${rule_id}`;

        $(`#${update_button_id}`).click((evt) => {
            // XXX Debug:
            //console.log(`Update button "${rule_id}" clicked!`);
            const service = $(`#service_${rule_id}`).val();
            const source = $(`#source_${rule_id}`).val();
            const comment = $(`#comment_${rule_id}`).val();
            let expiry = $(`#expiry_${rule_id}`).val();
            if (expiry && !expiry.match(/T\d{2}:\d{2}:\d{2}$/)) {
                // ISO 8601 needs seconds
                expiry += ':00';
            }

            if (!upsert_rule(rule_id, service, source, comment, expiry)) {
                // Note: Skip alerting, let jQuery handle required-fields.
                //alert(`Failed! Mandatory fields filled?`);
            }
            //evt.preventDefault();
        });
        $(`#${delete_button_id}`).click((evt) => {
            // XXX Debug:
            //console.log(`Delete button "${rule_id}" clicked!`);
            const service = $(`#service_${rule_id}`).val();
            const source = $(`#source_${rule_id}`).val();
            const confirm_message = `Really want to delete ${service} rule allowing ${source}?`;
            if (confirm(confirm_message)) {
                delete_rule(rule_id);
            }
            //evt.preventDefault();
        });

        // Form submit:
        $(`#${form_id}`).submit((evt) => {
            evt.preventDefault();
            console.log(`Internal error: Prevented form ${form_id} submit!`);
        });
    }
}

upsert_rule = (rule_id, service, source, comment, expiry) => {
    // XXX ToDo:
    //const form_valid = $(`#rules_form_${rule_id}`).validate();
    if (!service || !source) {
        return false;
    }

    const rule_id_to_use = rule_id === "new" ? "" : rule_id;
    $.ajax({
        url: `${window.location.href}/api/rules/${rule_id_to_use}`,
        method: rule_id_to_use ? 'put' : 'post',
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
        query_firewall_status();
    }).fail((data) => {
        if (data.responseJSON && data.responseJSON["error"]) {
            alert(`Failed!\n${data.responseJSON["error"]}`);
        } else {
            alert(`Failed!`);
        }
    });

    return true;
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
        query_firewall_status();
    }).fail((data) => {
        alert(`Failed!`);
    });
}

query_firewall_status = () => {
    $.ajax({
        url: `${window.location.href}/api/firewall/status`,
        method: 'get',
        context: document.body
    }).done((data) => {
        console.log("query_firewall_status(): got firewall update status");
        bastinon_needs_updating = data['updates_needed'];

        const update_button = $("#rules_into_effect_btn");
        const update_button_disabled = update_button.prop('disabled');
        if (bastinon_needs_updating) {
            if (update_button_disabled) {
                update_button.removeAttr('disabled');
            }
        } else {
            if (!update_button_disabled) {
                update_button.attr('disabled', true);
            }
        }
    });
}

rules_into_effect = () => {
    $.ajax({
        url: `${window.location.href}/api/firewall/update`,
        method: 'put',
        context: document.body
    }).done((data) => {
        console.log(`rules_into_effect(): firewall rules are in effect`);

        load_rules(true);
        query_firewall_status();
    }).fail((data) => {
        alert(`Failed!`);
    });
}

network_information = () => {
    // Mostly for public networks: Query for if network information was possibly available.
    // Make sure originating IP-address will be updated in any case.
    $.ajax({
        url: `${window.location.href}/api/remote/network`,
        method: 'get',
        context: document.body
    }).done((data) => {
        console.log("ready(): got network");
        const para = $("#network_info");
        if (data["query_done"]) {
            // Update network name
            const line_break = $('<br/>');
            para.empty();
            para.text(`Network: ${data["remote_network"]}, Organization: ${data["remote_org_name"]}`);
        } else {
            // Clean out contents of the <p>
            para.empty();
            para.text(`Non-public network`);
        }

        // Update IP-address
        $("#ip-address").val(data["remote_ip"]);

        update_rules();
    });
}

// end JavaScript
</script>
<footer>Version: <%= $version %></footer>
</body>
</html>
