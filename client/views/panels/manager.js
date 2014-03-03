define([
    'hr/utils',
    'hr/dom',
    'hr/hr',
    'models/command',
    'views/panels/base',
    'views/tabs/manager'
], function(_, $, hr, Command, PanelBaseView, TabsManager) {

    var PanelsView = hr.View.extend({
        className: "cb-panels-list",
        defaults: {},
        events: {},

        // Constructor
        initialize: function(options) {
            var that = this;
            PanelsView.__super__.initialize.apply(this, arguments);

            // Tabs
            this.tabs = new TabsManager({
                layout: 1,
                layouts: {
                    "Columns: 1": 1
                },
                tabMenu: false,
                newTab: false,
                maxTabsPerSection: 1
            }, this);
            this.tabs.$el.appendTo(this.$el);

            // Active panel
            this.activePanel = null;
            this.previousPanel = null;

            // Panels visibility
            this.visibilityCommand = new Command({}, {
                'type': "checkbox",
                'title': "Show Side Bar",
                'action': function(state) {
                    if (state) {
                        that.show();
                    } else {
                        that.close();
                    }
                }
            });
            this.on("state", function(state) {
                that.visibilityCommand.toggleFlag("active", state);
            });

            // Menu of panels choice
            this.panelsCommand = new Command({}, {
                'type': "menu",
                'title': "Panels"
            });

            // Panels map
            this.panels = {};

            return this;
        },

        // Register a new panel
        register: function(panelId, panelView, constructor, options) {
            constructor = _.extend(constructor || {}, {
                'panel': panelId
            });

            this.panels[panelId] = new panelView(constructor, this);
            this.panels[panelId].render();

            return this.panels[panelId];
        },

        // Render
        render: function() {
            return this.ready();
        },

        // Open a panel
        open: function(pId) {
            var opened = false;

            if (pId && this.panels[pId]) {
                opened = true;
                var tab = this.tabs.add(TabsManager.Panel, {}, {
                    'title': pId,
                    'uniqueId': pId
                });
                if (tab.$el.is(':empty')) {
                    this.panels[pId].$el.appendTo(tab.$el);
                }
            }

            this.previousPanel = this.activePanel || this.previousPanel;
            this.activePanel = pId;
            
            if (opened) {
                this.trigger("open", pId);
            } else {
                this.trigger("close");
            }
            this.trigger("state", opened);

            return this;
        },

        // Check if a panel is active
        isActive: function(pId) {
            var t = this.tabs.getById(pId);
            return !(t == null || !t.isActive());
        },

        // Close panel
        close: function() {
            return this.open(null);
        },

        // Show panels
        show: function() {
            return this.open(this.activePanel || this.previousPanel || _.first(_.keys(this.panels)));
        }
    });

    return PanelsView;
});