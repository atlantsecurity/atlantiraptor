// The last screens from the original interface that the new console
// has no replacement for yet: the server host page, server collections
// (with the offline collector builder), the multi-artifact event
// timeline and full-page notebook views. They render unchanged inside
// the new shell. Every other /classic address redirects to the new page
// (see AppShell). This module is loaded lazily so the new screens do
// not pay for the legacy code (notebooks, editors, VFS ...).
import React from 'react';
import PropTypes from 'prop-types';
import { Switch, Route } from 'react-router-dom';

import './legacy-styles.js';

import ClientSetterFromRoute from '../../components/clients/client_info.jsx';
import ServerInfo from '../../components/server/server-info.jsx';
import ServerFlowsView from '../../components/flows/server-flows-view.jsx';
import Notebook from '../../components/notebooks/notebook.jsx';
import EventMonitoring from '../../components/events/events.jsx';
import './legacy-icons.js';

export default function LegacyRoutes({ client, setClient }) {

  return (
    <div className="rx-legacy-host">
      <div id="content">
        <Switch>
          <Route path="/host/:client_id(server)/:action?">
            <ServerInfo />
          </Route>
          <Route path="/classic/collected/server/:flow_id?/:tab?">
            <ServerFlowsView />
          </Route>
          <Route path="/notebooks/:notebook_id/:artifact/:params_json?">
            <Notebook />
          </Route>
          <Route path="/classic/events/:client_id([^/]{7,})/:artifact?/:time?">
            <ClientSetterFromRoute client={client} setClient={setClient} />
            <EventMonitoring client={client} />
          </Route>
          <Route path="/classic/events/server/:artifact?/:time?">
            <EventMonitoring client={{ client_id: '' }} />
          </Route>
          <Route>
            <div className="no-content">Page not found</div>
          </Route>
        </Switch>
      </div>
    </div>
  );
}

LegacyRoutes.propTypes = {
  client: PropTypes.object,
  setClient: PropTypes.func,
};
