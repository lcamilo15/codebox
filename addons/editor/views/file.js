define([
    "views/base",
    "views/editor",
    "less!stylesheets/file.less"
], function(FilesBaseView, EditorView) {
    var _ = codebox.require("underscore");
    var $ = codebox.require("jQuery");
    var hr = codebox.require("hr/hr");
    var Dialogs = codebox.require("utils/dialogs");

    var FileEditorView = FilesBaseView.extend({
        className: "editor-files-editor",
        templateLoader: "addon.editor.templates",
        template: "file.html",
        events: {
            "click .action-file-fullscreen":    "toggleFullscreen",
            "click a[data-editormode]":         "changeEditorMode"
        },

        // Constructor
        initialize: function() {
            FileEditorView.__super__.initialize.apply(this, arguments);

            // Build editor
            this.editor = new EditorView();

            // Bind editor mode changements
            this.editor.on("change:mode", this.modeChanged, this);

            // Bind editor sync state changements
            this.editor.on("sync:state", function(state) {
                this.$(".action-editor-state").toggleClass("btn-danger", !state);
                this.$(".action-editor-state").toggleClass("btn-success", state);
            }, this);

            // Bind collaborators changements
            this.editor.sync.on("participants:change", this.updateParticipants, this);

            // Define file for code editor
            this.editor.sync.setFile(this.model, {
                'sync': this.options.edition
            });

            // Parent tab
            this.parent.on("tab:state", function(state) {
                if (state) this.editor.focus();
            }, this);
            this.editor.focus();
        },

        // Finish rendering
        finish: function() {
            // Add editor to content
            this.editor.$el.appendTo(this.$(".editor-inner"));
            this.modeChanged();
            this.updateParticipants();

            return FileEditorView.__super__.finish.apply(this, arguments);
        },

        // (action) Toggle fullscreen
        toggleFullscreen: function(e) {
            e.preventDefault();
            this.$el.toggleClass("mode-fullscreen");
        },

        // (action) change editor mode
        changeEditorMode: function(e) {
            e.preventDefault();
            var mode = $(e.currentTarget).data("editormode");
            this.editor.setMode(mode);
        },

        // (event) Mode changed
        modeChanged: function() {
            var mode = this.editor.getMode();
            this.$("a[data-editormode!='"+mode+"']").removeClass("active");
            this.$("a[data-editormode='"+mode+"']").addClass("active");
        },

        // Update participants list
        updateParticipants: function() {
            var $participants = this.$(".file-participants").empty();
            _.each(this.editor.sync.participants, function(participant) {
                $("<a>", {
                    'text': participant.user.get("name"),
                    'href': "#",
                    'class': "list-group-item",
                    'css': {
                        'border-left-color': participant.color
                    },
                    'click': function(e) { e.preventDefault(); }
                }).appendTo($participants);
            }, this);
        }
    });

    return FileEditorView;
});