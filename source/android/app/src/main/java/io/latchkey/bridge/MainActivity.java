package io.latchkey.bridge;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Latchkey main screen, 1.3.0-C UI.
 *
 * The shell (four pages, bottom tabs by default, switchable navigation drawer,
 * teal theme and component kit in {@link Ui}) is ported from the LocalKey
 * 1.3.0 variant C reference (flavors/C: DEFAULT_LAYOUT=tabs, LAYOUT_SWITCH=true).
 * All actions call the unchanged Latchkey 1.2.3 logic below (pairing, revoke,
 * key rotation, log view/export/clear, start/stop, permissions, battery).
 */
public final class MainActivity extends Activity {
    private static final int REQ_STORAGE = 11;
    private static final int REQ_NOTIFICATIONS = 12;

    // Variant C: tabs by default, user may switch to drawer (persisted).
    static final String VARIANT = "C";
    private static final String UI_PREFS = "latchkey_ui";
    private static final String PREF_LAYOUT = "layout_mode";
    private static final String LAYOUT_TABS = "tabs";
    private static final String LAYOUT_DRAWER = "drawer";
    private static final String STATE_PAGE = "active_page";
    private static final int PAGE_HOME = 0;
    private static final int PAGE_CONNECT = 1;
    private static final int PAGE_AUDIT = 2;
    private static final int PAGE_SETTINGS = 3;

    private String layoutMode = LAYOUT_TABS;
    private int activePage = PAGE_HOME;
    private View[] pages;
    private FrameLayout pageHost;
    private View drawerScrim;
    private LinearLayout drawerPanel;
    private boolean drawerOpen;
    private final List<NavBinding> navBindings = new ArrayList<NavBinding>();

    // Home
    private View statusDot;
    private TextView statusPill;
    private TextView statusText;
    private TextView endpointText;
    private Button startBtn;
    private TextView readinessCount;
    private TextView permText;
    private Button permBtn;
    private TextView notifyText;
    private Button notifyBtn;
    private TextView batteryText;
    private Button batteryBtn;
    private TextView statsText;
    // Connect
    private TextView pairHint;
    private Button pairBtn;
    private TextView clientsText;
    private TextView clientsCount;
    private LinearLayout clientsContainer;
    private Button revokeClientsBtn;
    private TextView keyText;
    private TextView fingerprintText;
    private Button revealBtn;
    // Audit
    private TextView auditSummary;
    private TextView auditText;

    private String key = "";
    private boolean keyVisible = false;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat clock = new SimpleDateFormat("HH:mm:ss", Locale.US);

    private final Runnable ticker = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 1000L);
        }
    };

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventLog.init(this);
        EventLog.info("app", "create", "MainActivity created");
        String saved = getSharedPreferences(UI_PREFS, MODE_PRIVATE).getString(PREF_LAYOUT, LAYOUT_TABS);
        layoutMode = LAYOUT_DRAWER.equals(saved) ? LAYOUT_DRAWER : LAYOUT_TABS;
        if (savedInstanceState != null) {
            activePage = savedInstanceState.getInt(STATE_PAGE, PAGE_HOME);
            if (activePage < PAGE_HOME || activePage > PAGE_SETTINGS) activePage = PAGE_HOME;
        }
        View root = buildShell();
        setContentView(root);
        applyInsets(root);
        hardenTouches(getWindow().getDecorView());

        key = KeyStoreManager.getOrCreateKey(this);
        updateKeyViews();
        refresh();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_PAGE, activePage);
    }

    /** Edge-to-edge safe: pad the whole shell by system bars + display cutout. */
    private void applyInsets(View root) {
        root.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override
            public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                int left = insets.getSystemWindowInsetLeft();
                int top = insets.getSystemWindowInsetTop();
                int right = insets.getSystemWindowInsetRight();
                int bottom = insets.getSystemWindowInsetBottom();
                if (Build.VERSION.SDK_INT >= 30) {
                    Insets bars = insets.getInsets(WindowInsets.Type.systemBars()
                            | WindowInsets.Type.displayCutout());
                    left = bars.left;
                    top = bars.top;
                    right = bars.right;
                    bottom = bars.bottom;
                }
                view.setPadding(left, top, right, bottom);
                return insets;
            }
        });
        root.requestApplyInsets();
    }

    @Override
    protected void onResume() {
        super.onResume();
        EventLog.info("app", "resume", "MainActivity resumed");
        handler.removeCallbacks(ticker);
        refresh();
        handler.postDelayed(ticker, 1000L);
    }

    @Override
    protected void onPause() {
        EventLog.info("app", "pause", "MainActivity paused");
        handler.removeCallbacks(ticker);
        if (keyVisible) {
            keyVisible = false;
            updateKeyViews();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        EventLog.info("app", "destroy", "MainActivity destroyed");
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (drawerOpen) {
            closeDrawer();
            return;
        }
        if (activePage != PAGE_HOME) {
            selectPage(PAGE_HOME);
            return;
        }
        super.onBackPressed();
    }

    // ---------------------------------------------------------------- shell

    private boolean isDrawerLayout() {
        return LAYOUT_DRAWER.equals(layoutMode);
    }

    private View buildShell() {
        pages = new View[] { buildHomePage(), buildConnectPage(), buildAuditPage(), buildSettingsPage() };
        pageHost = new FrameLayout(this);
        pageHost.setBackgroundColor(Ui.BG);
        for (int i = 0; i < pages.length; i++) {
            pages[i].setVisibility(i == activePage ? View.VISIBLE : View.GONE);
            pageHost.addView(pages[i], new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }
        return isDrawerLayout() ? buildDrawerShell() : buildTabShell();
    }

    private View buildTabShell() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.BG);
        root.addView(appBar(false), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(pageHost, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(bottomNav(), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        updateNavigation();
        return root;
    }

    private View buildDrawerShell() {
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Ui.BG);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.addView(appBar(true), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(pageHost, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        root.addView(content, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        drawerScrim = new View(this);
        drawerScrim.setBackgroundColor(Color.BLACK);
        drawerScrim.setAlpha(0f);
        drawerScrim.setVisibility(View.GONE);
        drawerScrim.setClickable(true);
        drawerScrim.setContentDescription("Close navigation");
        drawerScrim.setOnClickListener(v -> closeDrawer());
        root.addView(drawerScrim, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        drawerPanel = buildDrawer();
        int screen = getResources().getDisplayMetrics().widthPixels;
        // Never wider than the screen minus a 54dp tap-out strip (small phones).
        int width = Math.min(Ui.dp(this, 310), Math.max(Math.min(Ui.dp(this, 260), screen - Ui.dp(this, 54)),
                screen - Ui.dp(this, 54)));
        root.addView(drawerPanel, new FrameLayout.LayoutParams(
                width, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.START));
        drawerPanel.setVisibility(View.INVISIBLE);
        drawerPanel.setTranslationX(-width);
        updateNavigation();
        return root;
    }

    private View appBar(boolean menuMode) {
        LinearLayout bar = row();
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setBackgroundColor(Ui.BG);
        bar.setPadding(Ui.dp(this, 20), Ui.dp(this, 10), Ui.dp(this, 20), Ui.dp(this, 8));
        if (menuMode) {
            bar.addView(navIconButton(R.drawable.ic_menu, "Open navigation", this::openDrawer),
                    new LinearLayout.LayoutParams(Ui.dp(this, 48), Ui.dp(this, 48)));
        } else {
            bar.addView(Ui.iconBox(this, R.drawable.ic_key, Ui.TEAL, 36, 19),
                    new LinearLayout.LayoutParams(Ui.dp(this, 36), Ui.dp(this, 36)));
        }
        TextView title = Ui.text(this, "Latchkey", 22f, Ui.TEXT, Ui.sansBold());
        title.setSingleLine(true);
        title.setEllipsize(TextUtils.TruncateAt.END);
        if (Build.VERSION.SDK_INT >= 28) title.setAccessibilityHeading(true);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        titleParams.leftMargin = Ui.dp(this, 11);
        bar.addView(title, titleParams);
        bar.addView(Ui.pill(this, "v" + ServerRuntime.VERSION,
                Ui.MUTED, Ui.withAlpha(Ui.BORDER, 120), Ui.BORDER));
        return bar;
    }

    private View bottomNav() {
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setBackgroundColor(Ui.BG);
        bar.addView(Ui.divider(this));
        LinearLayout items = row();
        items.setPadding(Ui.dp(this, 10), Ui.dp(this, 6), Ui.dp(this, 10), Ui.dp(this, 8));
        items.addView(tabItem(PAGE_HOME, "Home", R.drawable.ic_home), new LinearLayout.LayoutParams(0, Ui.dp(this, 54), 1f));
        items.addView(tabItem(PAGE_CONNECT, "Connect", R.drawable.ic_link), new LinearLayout.LayoutParams(0, Ui.dp(this, 54), 1f));
        items.addView(tabItem(PAGE_AUDIT, "Audit", R.drawable.ic_log), new LinearLayout.LayoutParams(0, Ui.dp(this, 54), 1f));
        items.addView(tabItem(PAGE_SETTINGS, "Settings", R.drawable.ic_settings), new LinearLayout.LayoutParams(0, Ui.dp(this, 54), 1f));
        bar.addView(items);
        return bar;
    }

    private View tabItem(final int page, String label, int iconRes) {
        LinearLayout item = new LinearLayout(this);
        item.setOrientation(LinearLayout.VERTICAL);
        item.setGravity(Gravity.CENTER);
        item.setClickable(true);
        item.setFocusable(true);
        item.setContentDescription(label);
        item.setOnClickListener(v -> selectPage(page));
        ImageView icon = Ui.icon(this, iconRes, Ui.MUTED, 21);
        item.addView(icon, new LinearLayout.LayoutParams(Ui.dp(this, 21), Ui.dp(this, 21)));
        TextView text = Ui.text(this, label, 10.5f, Ui.MUTED, Ui.sansMedium());
        text.setPadding(0, Ui.dp(this, 3), 0, 0);
        text.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        item.addView(text);
        navBindings.add(new NavBinding(item, icon, text, page));
        return item;
    }

    private LinearLayout buildDrawer() {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(Ui.dp(this, 20), Ui.dp(this, 20), Ui.dp(this, 20), Ui.dp(this, 22));
        GradientDrawable background = new GradientDrawable();
        background.setColor(Ui.CARD_DEEP);
        background.setStroke(Ui.dp(this, 1), Ui.BORDER);
        float radius = Ui.dp(this, 24);
        background.setCornerRadii(new float[] { 0, 0, radius, radius, radius, radius, 0, 0 });
        panel.setBackground(background);
        panel.setElevation(Ui.dp(this, 18));
        panel.setClickable(true);

        LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(Ui.iconBox(this, R.drawable.ic_key, Ui.TEAL, 44, 23),
                new LinearLayout.LayoutParams(Ui.dp(this, 44), Ui.dp(this, 44)));
        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(Ui.dp(this, 12), 0, Ui.dp(this, 8), 0);
        copy.addView(Ui.text(this, "Latchkey", 23f, Ui.TEXT, Ui.sansBold()));
        copy.addView(Ui.text(this, "v" + ServerRuntime.VERSION, 10.5f, Ui.MUTED, Ui.mono()));
        header.addView(copy, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(navIconButton(R.drawable.ic_close, "Close navigation", this::closeDrawer),
                new LinearLayout.LayoutParams(Ui.dp(this, 48), Ui.dp(this, 48)));
        panel.addView(header);

        TextView label = Ui.section(this, "Navigation");
        label.setPadding(0, Ui.dp(this, 28), 0, Ui.dp(this, 8));
        panel.addView(label);
        panel.addView(drawerItem(PAGE_HOME, "Home", R.drawable.ic_home));
        panel.addView(drawerItem(PAGE_CONNECT, "Connect", R.drawable.ic_link));
        panel.addView(drawerItem(PAGE_AUDIT, "Audit", R.drawable.ic_log));
        panel.addView(drawerItem(PAGE_SETTINGS, "Settings", R.drawable.ic_settings));
        panel.addView(new View(this), new LinearLayout.LayoutParams(0, 0, 1f));
        panel.addView(Ui.divider(this));
        TextView note = Ui.text(this, "Loopback only · AES-256-GCM\nVariant " + VARIANT
                + " · port " + ServerRuntime.PORT, 10f, Ui.FAINT, Ui.sans());
        note.setLineSpacing(Ui.dp(this, 3), 1f);
        note.setPadding(0, Ui.dp(this, 14), 0, 0);
        panel.addView(note);
        return panel;
    }

    private View drawerItem(final int page, String label, int iconRes) {
        LinearLayout item = row();
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(Ui.dp(this, 14), 0, Ui.dp(this, 14), 0);
        item.setClickable(true);
        item.setFocusable(true);
        item.setContentDescription(label);
        item.setOnClickListener(v -> selectPage(page));
        ImageView icon = Ui.icon(this, iconRes, Ui.MUTED, 22);
        item.addView(icon, new LinearLayout.LayoutParams(Ui.dp(this, 22), Ui.dp(this, 22)));
        TextView text = Ui.text(this, label, 15f, Ui.MUTED, Ui.sansMedium());
        text.setPadding(Ui.dp(this, 13), 0, 0, 0);
        text.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        item.addView(text, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        navBindings.add(new NavBinding(item, icon, text, page));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 50));
        params.topMargin = Ui.dp(this, 3);
        item.setLayoutParams(params);
        return item;
    }

    private FrameLayout navIconButton(int iconRes, String description, final Runnable action) {
        FrameLayout box = new FrameLayout(this);
        box.setBackground(Ui.card(this, Ui.withAlpha(Ui.CARD, 170), Ui.BORDER, 11));
        box.setClickable(true);
        box.setFocusable(true);
        box.setContentDescription(description);
        box.addView(Ui.icon(this, iconRes, Ui.MUTED, 21), new FrameLayout.LayoutParams(
                Ui.dp(this, 21), Ui.dp(this, 21), Gravity.CENTER));
        box.setOnClickListener(v -> action.run());
        return box;
    }

    private void updateNavigation() {
        for (NavBinding binding : navBindings) {
            boolean selected = binding.page == activePage;
            binding.container.setSelected(selected);
            binding.container.setBackground(selected
                    ? Ui.card(this, Ui.withAlpha(Ui.TEAL, 18), Ui.withAlpha(Ui.TEAL, 38), 14)
                    : null);
            binding.icon.setColorFilter(selected ? Ui.TEAL : Ui.MUTED);
            binding.label.setTextColor(selected ? Ui.TEAL : Ui.MUTED);
            binding.container.setContentDescription(binding.label.getText()
                    + (selected ? ", selected" : ""));
        }
    }

    private void selectPage(int page) {
        if (pages == null || page < 0 || page >= pages.length) return;
        activePage = page;
        for (int i = 0; i < pages.length; i++) {
            pages[i].setVisibility(i == activePage ? View.VISIBLE : View.GONE);
        }
        updateNavigation();
        if (drawerOpen) closeDrawer();
        if (page == PAGE_CONNECT) updateClientViews();
        if (page == PAGE_AUDIT) updateAuditView();
        pages[page].sendAccessibilityEvent(android.view.accessibility.AccessibilityEvent.TYPE_VIEW_FOCUSED);
    }

    private void openDrawer() {
        if (drawerPanel == null || drawerOpen) return;
        drawerOpen = true;
        int width = drawerPanel.getWidth() > 0 ? drawerPanel.getWidth() : Ui.dp(this, 304);
        drawerPanel.setVisibility(View.VISIBLE);
        drawerPanel.setTranslationX(-width);
        drawerScrim.setVisibility(View.VISIBLE);
        drawerScrim.setAlpha(0f);
        pageHost.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS);
        drawerPanel.animate().translationX(0f).setDuration(220).start();
        drawerScrim.animate().alpha(0.55f).setDuration(180).start();
    }

    private void closeDrawer() {
        if (drawerPanel == null || !drawerOpen) return;
        drawerOpen = false;
        int width = drawerPanel.getWidth() > 0 ? drawerPanel.getWidth() : Ui.dp(this, 304);
        pageHost.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_AUTO);
        drawerPanel.animate().translationX(-width).setDuration(180)
                .withEndAction(() -> drawerPanel.setVisibility(View.INVISIBLE)).start();
        drawerScrim.animate().alpha(0f).setDuration(180)
                .withEndAction(() -> drawerScrim.setVisibility(View.GONE)).start();
    }

    // ---------------------------------------------------------------- pages

    private View buildHomePage() {
        Page page = newPage("Home", "Status", getString(R.string.tagline) + ".", Ui.TEAL);
        page.body.addView(Ui.pill(this, getString(R.string.pill),
                Ui.TEAL, Ui.withAlpha(Ui.TEAL, 22), Ui.withAlpha(Ui.TEAL, 62)));
        page.body.addView(statusCard(), topParams(14));
        page.body.addView(readinessCard(), topParams(14));
        page.body.addView(footer(), topParams(26));
        return page.scroll;
    }

    private View buildConnectPage() {
        Page page = newPage("Connect", "Connect", "Pair assistants and keep keys on-device.", Ui.VIOLET);
        page.body.addView(assistantCard(), topParams(10));
        page.body.addView(clientsCard(), topParams(14));
        page.body.addView(keyCard(), topParams(14));
        page.body.addView(footer(), topParams(26));
        return page.scroll;
    }

    private View buildAuditPage() {
        Page page = newPage("Audit", "Audit", "A local record of bridge activity.", Ui.TEAL);
        page.body.addView(auditCard(), topParams(10));
        page.body.addView(auditViewerCard(), topParams(14));
        page.body.addView(footer(), topParams(26));
        return page.scroll;
    }

    private View buildSettingsPage() {
        Page page = newPage("Settings", "Settings", "Choose how Latchkey moves and behaves.", Ui.TEAL);
        page.body.addView(layoutCard(), topParams(10));
        page.body.addView(aboutCard(), topParams(14));
        page.body.addView(footer(), topParams(26));
        return page.scroll;
    }

    private Page newPage(String eyebrow, String title, String subtitle, int accent) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Ui.BG);
        scroll.setClipToPadding(false);
        scroll.setVerticalScrollBarEnabled(false);
        scroll.setOverScrollMode(View.OVER_SCROLL_NEVER);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(Ui.dp(this, 20), Ui.dp(this, 8), Ui.dp(this, 20), Ui.dp(this, 34));
        scroll.addView(body);
        TextView eye = Ui.eyebrow(this, eyebrow);
        eye.setTextColor(accent);
        body.addView(eye);
        TextView heading = Ui.text(this, title, 27f, Ui.TEXT, Ui.sansBold());
        heading.setPadding(0, Ui.dp(this, 5), 0, 0);
        if (Build.VERSION.SDK_INT >= 28) heading.setAccessibilityHeading(true);
        body.addView(heading);
        TextView sub = Ui.text(this, subtitle, 12.5f, Ui.MUTED, Ui.sans());
        sub.setPadding(0, Ui.dp(this, 5), 0, Ui.dp(this, 14));
        body.addView(sub);
        return new Page(scroll, body);
    }

    private LinearLayout statusCard() {
        LinearLayout card = vcard(20, 18, Ui.gradient(this, Color.rgb(16, 34, 45), Color.rgb(10, 17, 28),
                Ui.withAlpha(Ui.TEAL, 58), 20));
        LinearLayout top = row();
        top.setGravity(Gravity.CENTER_VERTICAL);
        statusDot = Ui.circle(this, Ui.FAINT, 9);
        top.addView(statusDot);
        TextView eyebrow = Ui.eyebrow(this, "Server");
        eyebrow.setPadding(Ui.dp(this, 8), 0, 0, 0);
        top.addView(eyebrow);
        top.addView(new View(this), new LinearLayout.LayoutParams(0, 1, 1f));
        statusPill = Ui.pill(this, "OFFLINE", Ui.FAINT, Ui.withAlpha(Ui.FAINT, 18), Ui.BORDER);
        top.addView(statusPill);
        card.addView(top);

        statusText = Ui.text(this, getString(R.string.status_stopped), 27f, Ui.TEXT, Ui.sansBold());
        statusText.setPadding(0, Ui.dp(this, 12), 0, 0);
        statusText.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        card.addView(statusText);
        endpointText = Ui.text(this, "127.0.0.1:" + ServerRuntime.PORT, 12.5f, Ui.MUTED, Ui.mono());
        endpointText.setPadding(0, Ui.dp(this, 5), 0, 0);
        card.addView(endpointText);

        startBtn = Ui.button(this, getString(R.string.btn_start), Ui.KIND_PRIMARY, Ui.TEAL);
        startBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (ServerRuntime.running) {
                    EventLog.info("ui", "stop", "stop requested from activity");
                    LatchkeyService.stop(MainActivity.this);
                    handler.postDelayed(new Runnable() {
                        @Override
                        public void run() {
                            refresh();
                        }
                    }, 350L);
                } else {
                    startServer();
                }
            }
        });
        LinearLayout.LayoutParams startParams = topParams(17);
        card.addView(startBtn, startParams);

        statsText = Ui.text(this, "", 10.5f, Ui.MUTED, Ui.mono());
        statsText.setLineSpacing(Ui.dp(this, 2), 1f);
        statsText.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        statsText.setBackground(Ui.inset(this, 12));
        card.addView(statsText, topParams(12));
        return card;
    }

    private LinearLayout readinessCard() {
        LinearLayout panel = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.withAlpha(Ui.AMBER, 80), 20));
        panel.setPadding(Ui.dp(this, 18), Ui.dp(this, 17), Ui.dp(this, 18), Ui.dp(this, 10));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Device readiness", 18f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        readinessCount = Ui.pill(this, "0/3 SETUP", Ui.AMBER, Ui.withAlpha(Ui.AMBER, 18), Ui.withAlpha(Ui.AMBER, 62));
        titleRow.addView(readinessCount);
        panel.addView(titleRow);

        ReadinessRow file = addReadinessRow(panel, R.drawable.ic_folder, Ui.TEAL, "File access");
        permText = file.state;
        permBtn = file.action;
        permBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                EventLog.info("ui", "permission", "opened all-files settings");
                openAllFilesSettings();
            }
        });
        ReadinessRow notify = addReadinessRow(panel, R.drawable.ic_bell, Ui.AMBER, "Notifications");
        notifyText = notify.state;
        notifyBtn = notify.action;
        notifyBtn.setOnClickListener(v -> notificationAction());
        ReadinessRow battery = addReadinessRow(panel, R.drawable.ic_battery, Ui.VIOLET, "Battery optimization");
        batteryText = battery.state;
        batteryBtn = battery.action;
        batteryBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                EventLog.info("ui", "battery", "battery exemption requested");
                requestBatteryExemption();
            }
        });
        return panel;
    }

    private ReadinessRow addReadinessRow(LinearLayout parent, int iconRes, int tint, String title) {
        if (parent.getChildCount() > 1) parent.addView(Ui.divider(this));
        LinearLayout row = row();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, Ui.dp(this, 11), 0, Ui.dp(this, 11));
        row.addView(Ui.iconBox(this, iconRes, tint, 36, 18), new LinearLayout.LayoutParams(Ui.dp(this, 36), Ui.dp(this, 36)));
        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(Ui.dp(this, 12), 0, Ui.dp(this, 8), 0);
        copy.addView(Ui.text(this, title, 14f, Ui.TEXT, Ui.sansMedium()));
        TextView state = Ui.text(this, "Checking…", 11.5f, Ui.MUTED, Ui.sans());
        state.setPadding(0, Ui.dp(this, 2), 0, 0);
        copy.addView(state);
        row.addView(copy, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button action = Ui.button(this, "Manage", Ui.KIND_SECONDARY, tint, true);
        action.setContentDescription("Manage " + title);
        row.addView(action, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, Ui.dp(this, 48)));
        parent.addView(row);
        return new ReadinessRow(state, action);
    }

    private LinearLayout assistantCard() {
        LinearLayout card = vcard(18, 17, Ui.gradient(this, Color.rgb(27, 21, 43), Color.rgb(14, 12, 24),
                Ui.withAlpha(Ui.VIOLET, 78), 20));
        card.addView(Ui.text(this, getString(R.string.pair_title), 18f, Ui.TEXT, Ui.sansBold()));
        pairHint = Ui.text(this, getString(R.string.pair_hint), 12.5f, Ui.MUTED, Ui.sans());
        pairHint.setLineSpacing(0f, 1.12f);
        pairHint.setPadding(0, Ui.dp(this, 5), 0, 0);
        pairHint.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        card.addView(pairHint);
        clientsText = Ui.text(this, getString(R.string.clients_none), 12f, Ui.VIOLET, Ui.sansMedium());
        clientsText.setPadding(0, Ui.dp(this, 12), 0, 0);
        card.addView(clientsText);
        pairBtn = Ui.button(this, getString(R.string.pair_btn), Ui.KIND_PRIMARY, Ui.VIOLET, true);
        pairBtn.setOnClickListener(v -> pairAssistant());
        LinearLayout.LayoutParams pairParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48));
        pairParams.topMargin = Ui.dp(this, 14);
        card.addView(pairBtn, pairParams);
        return card;
    }

    private LinearLayout clientsCard() {
        LinearLayout card = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Paired clients", 18f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        clientsCount = Ui.pill(this, "0", Ui.VIOLET, Ui.withAlpha(Ui.VIOLET, 18), Ui.withAlpha(Ui.VIOLET, 62));
        titleRow.addView(clientsCount);
        card.addView(titleRow);
        TextView description = Ui.text(this,
                "Each paired assistant has its own key. Revoking all also rotates the legacy key.",
                12f, Ui.MUTED, Ui.sans());
        description.setPadding(0, Ui.dp(this, 5), 0, Ui.dp(this, 7));
        card.addView(description);
        clientsContainer = new LinearLayout(this);
        clientsContainer.setOrientation(LinearLayout.VERTICAL);
        card.addView(clientsContainer);
        revokeClientsBtn = Ui.button(this, "Revoke all & rotate key", Ui.KIND_DANGER, Ui.RED, true);
        revokeClientsBtn.setOnClickListener(v -> confirmRevokeClients());
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48));
        p.topMargin = Ui.dp(this, 8);
        card.addView(revokeClientsBtn, p);
        return card;
    }

    private LinearLayout keyCard() {
        LinearLayout card = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Legacy access key", 18f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleRow.addView(Ui.pill(this, "LEGACY", Ui.AMBER, Ui.withAlpha(Ui.AMBER, 18), Ui.withAlpha(Ui.AMBER, 62)));
        card.addView(titleRow);
        TextView description = Ui.text(this, getString(R.string.key_hint), 12.5f, Ui.MUTED, Ui.sans());
        description.setLineSpacing(0f, 1.12f);
        description.setPadding(0, Ui.dp(this, 5), 0, 0);
        card.addView(description);
        TextView fpLabel = Ui.section(this, "Fingerprint");
        fpLabel.setPadding(0, Ui.dp(this, 14), 0, Ui.dp(this, 4));
        card.addView(fpLabel);
        fingerprintText = Ui.text(this, "", 11.5f, Ui.MUTED, Ui.mono());
        fingerprintText.setTextIsSelectable(true);
        card.addView(fingerprintText);
        TextView keyLabel = Ui.section(this, "Key");
        keyLabel.setPadding(0, Ui.dp(this, 13), 0, Ui.dp(this, 5));
        card.addView(keyLabel);
        keyText = Ui.text(this, "", 13.5f, Ui.TEXT, Ui.mono());
        keyText.setPadding(Ui.dp(this, 14), Ui.dp(this, 12), Ui.dp(this, 14), Ui.dp(this, 12));
        keyText.setBackground(Ui.inset(this, 12));
        keyText.setOnClickListener(v -> toggleReveal());
        card.addView(keyText);
        LinearLayout actions = row();
        actions.setPadding(0, Ui.dp(this, 13), 0, 0);
        revealBtn = Ui.button(this, "Reveal", Ui.KIND_SECONDARY, Ui.TEAL, true);
        revealBtn.setOnClickListener(v -> toggleReveal());
        actions.addView(revealBtn, new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f));
        Button copy = Ui.button(this, "Copy", Ui.KIND_SECONDARY, Ui.TEAL, true);
        copy.setContentDescription("Copy legacy key");
        copy.setOnClickListener(v -> copyKey());
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f);
        cp.leftMargin = Ui.dp(this, 6);
        cp.rightMargin = Ui.dp(this, 6);
        actions.addView(copy, cp);
        Button rotate = Ui.button(this, "Rotate", Ui.KIND_DANGER, Ui.RED, true);
        rotate.setContentDescription("Rotate legacy key");
        rotate.setOnClickListener(v -> {
            EventLog.info("ui", "regenerate", "key regeneration confirmation opened");
            confirmRegenerate();
        });
        actions.addView(rotate, new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f));
        card.addView(actions);
        return card;
    }

    private LinearLayout auditCard() {
        LinearLayout card = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Activity log", 18f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleRow.addView(Ui.pill(this, "JSONL", Ui.TEAL, Ui.withAlpha(Ui.TEAL, 18), Ui.withAlpha(Ui.TEAL, 58)));
        card.addView(titleRow);
        auditSummary = Ui.text(this, "", 12f, Ui.MUTED, Ui.sans());
        auditSummary.setPadding(0, Ui.dp(this, 5), 0, 0);
        card.addView(auditSummary);
        LinearLayout actions = row();
        actions.setPadding(0, Ui.dp(this, 13), 0, 0);
        Button view = Ui.button(this, getString(R.string.btn_view_log), Ui.KIND_SECONDARY, Ui.TEAL, true);
        view.setOnClickListener(v -> showLog());
        LinearLayout.LayoutParams vp = new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f);
        vp.rightMargin = Ui.dp(this, 6);
        actions.addView(view, vp);
        Button export = Ui.button(this, getString(R.string.btn_export_log), Ui.KIND_PRIMARY, Ui.TEAL, true);
        export.setOnClickListener(v -> exportLog());
        LinearLayout.LayoutParams ep = new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f);
        ep.rightMargin = Ui.dp(this, 6);
        actions.addView(export, ep);
        Button clear = Ui.button(this, getString(R.string.btn_clear_log), Ui.KIND_DANGER, Ui.RED, true);
        clear.setOnClickListener(v -> clearLog());
        actions.addView(clear, new LinearLayout.LayoutParams(0, Ui.dp(this, 48), 1f));
        card.addView(actions);
        return card;
    }

    private LinearLayout auditViewerCard() {
        LinearLayout card = vcard(16, 15, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Recent events", 16f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleRow.addView(Ui.pill(this, "LATEST 80", Ui.FAINT, Ui.withAlpha(Ui.FAINT, 16), Ui.BORDER));
        card.addView(titleRow);
        auditText = Ui.text(this, "No events yet.", 9.5f, Ui.TEXT, Ui.mono());
        auditText.setTextIsSelectable(true);
        auditText.setLineSpacing(Ui.dp(this, 2), 1f);
        auditText.setPadding(Ui.dp(this, 12), Ui.dp(this, 11), Ui.dp(this, 12), Ui.dp(this, 11));
        auditText.setBackground(Ui.inset(this, 12));
        card.addView(auditText, topParams(10));
        return card;
    }

    private LinearLayout layoutCard() {
        LinearLayout card = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        LinearLayout titleRow = row();
        titleRow.setGravity(Gravity.CENTER_VERTICAL);
        titleRow.addView(Ui.text(this, "Navigation layout", 18f, Ui.TEXT, Ui.sansBold()),
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        titleRow.addView(Ui.pill(this, "LAYOUT A / B", Ui.TEAL, Ui.withAlpha(Ui.TEAL, 18), Ui.withAlpha(Ui.TEAL, 58)));
        card.addView(titleRow);
        TextView description = Ui.text(this, "Choose how to move between the four Latchkey screens.",
                12.5f, Ui.MUTED, Ui.sans());
        description.setPadding(0, Ui.dp(this, 5), 0, Ui.dp(this, 12));
        card.addView(description);
        card.addView(layoutChoice("A", "Bottom tabs", LAYOUT_TABS, R.drawable.ic_home, Ui.TEAL));
        card.addView(layoutChoice("B", "Navigation drawer", LAYOUT_DRAWER, R.drawable.ic_menu, Ui.VIOLET));
        return card;
    }

    private View layoutChoice(String code, String title, final String mode, int iconRes, int accent) {
        boolean selected = mode.equals(layoutMode);
        LinearLayout row = row();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(Ui.dp(this, 48));
        row.setPadding(Ui.dp(this, 12), Ui.dp(this, 11), Ui.dp(this, 12), Ui.dp(this, 11));
        row.setBackground(selected
                ? Ui.card(this, Ui.withAlpha(accent, 18), Ui.withAlpha(accent, 72), 14)
                : Ui.card(this, Ui.CARD_DEEP, Ui.BORDER, 14));
        row.setClickable(true);
        row.setFocusable(true);
        row.setContentDescription(title + (selected ? ", selected" : ""));
        row.addView(Ui.iconBox(this, iconRes, selected ? accent : Ui.MUTED, 36, 18),
                new LinearLayout.LayoutParams(Ui.dp(this, 36), Ui.dp(this, 36)));
        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(Ui.dp(this, 11), 0, Ui.dp(this, 6), 0);
        copy.addView(Ui.text(this, title, 14f, Ui.TEXT, Ui.sansMedium()));
        copy.addView(Ui.text(this, "Layout " + code, 10.5f, Ui.MUTED, Ui.sans()));
        row.addView(copy, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        if (selected) {
            row.addView(Ui.icon(this, R.drawable.ic_check, accent, 18),
                    new LinearLayout.LayoutParams(Ui.dp(this, 18), Ui.dp(this, 18)));
        }
        row.setOnClickListener(v -> chooseLayout(mode));
        row.setLayoutParams(topParams(7));
        return row;
    }

    private void chooseLayout(String mode) {
        if (mode.equals(layoutMode)) return;
        getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit().putString(PREF_LAYOUT, mode).apply();
        EventLog.info("ui", "layout", "layout changed to " + mode);
        recreate();
    }

    private LinearLayout aboutCard() {
        LinearLayout card = vcard(18, 17, Ui.card(this, Ui.CARD, Ui.BORDER, 20));
        card.setPadding(Ui.dp(this, 18), Ui.dp(this, 17), Ui.dp(this, 18), Ui.dp(this, 10));
        card.addView(Ui.text(this, "About Latchkey", 18f, Ui.TEXT, Ui.sansBold()));
        TextView description = Ui.text(this, getString(R.string.footer), 12.5f, Ui.MUTED, Ui.sans());
        description.setPadding(0, Ui.dp(this, 5), 0, Ui.dp(this, 4));
        card.addView(description);
        addAboutRow(card, "Version", ServerRuntime.VERSION + " (" + versionCode() + ")");
        addAboutRow(card, "UI variant", VARIANT + " · " + (isDrawerLayout() ? "Navigation drawer" : "Bottom tabs"));
        addAboutRow(card, "Endpoint", "127.0.0.1:" + ServerRuntime.PORT);
        addAboutRow(card, "Package", getPackageName());
        return card;
    }

    private String versionCode() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            return String.valueOf(Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode);
        } catch (Exception e) {
            return "?";
        }
    }

    private void addAboutRow(LinearLayout parent, String label, String value) {
        parent.addView(Ui.divider(this));
        LinearLayout row = row();
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, Ui.dp(this, 12), 0, Ui.dp(this, 12));
        row.addView(Ui.text(this, label, 13f, Ui.MUTED, Ui.sans()));
        TextView valueView = Ui.text(this, value, 12.5f, Ui.TEXT, Ui.mono());
        valueView.setSingleLine(true);
        valueView.setEllipsize(TextUtils.TruncateAt.END);
        valueView.setGravity(Gravity.END);
        row.addView(valueView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        parent.addView(row);
    }

    private LinearLayout footer() {
        LinearLayout footer = row();
        footer.setGravity(Gravity.TOP);
        footer.addView(Ui.icon(this, R.drawable.ic_shield, Ui.FAINT, 14),
                new LinearLayout.LayoutParams(Ui.dp(this, 14), Ui.dp(this, 14)));
        TextView note = Ui.text(this, "Loopback only · AES-256-GCM · pairing links are single-use\n"
                + "Android/data and Android/obb may remain restricted.", 10.5f, Ui.FAINT, Ui.sans());
        note.setLineSpacing(Ui.dp(this, 3), 1f);
        note.setPadding(Ui.dp(this, 8), 0, 0, 0);
        footer.addView(note, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return footer;
    }

    private LinearLayout vcard(int padH, int padV, android.graphics.drawable.Drawable bg) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(Ui.dp(this, padH), Ui.dp(this, padV), Ui.dp(this, padH), Ui.dp(this, padV));
        card.setBackground(bg);
        return card;
    }

    private LinearLayout row() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        return row;
    }

    private LinearLayout.LayoutParams topParams(int topDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = Ui.dp(this, topDp);
        return params;
    }

    /** Reject taps delivered through an overlay (tapjacking), as in LocalKey. */
    private static void hardenTouches(View view) {
        view.setFilterTouchesWhenObscured(true);
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                hardenTouches(group.getChildAt(i));
            }
        }
    }

    // ---------------------------------------------------------------- state

    private void toggleReveal() {
        keyVisible = !keyVisible;
        EventLog.info("ui", "key", keyVisible ? "key revealed" : "key hidden");
        updateKeyViews();
    }

    private void updateKeyViews() {
        keyText.setText(keyVisible ? key : getString(R.string.key_hidden));
        keyText.setContentDescription(keyVisible ? "Legacy key shown" : "Legacy key hidden, tap to reveal");
        if (revealBtn != null) revealBtn.setText(keyVisible ? "Hide" : "Reveal");
        try {
            String fingerprint = Crypto.fingerprint(Crypto.decodeKey(key));
            if (KeyStoreManager.isPersisted()) {
                fingerprintText.setText("SHA-256  " + fingerprint);
                fingerprintText.setTextColor(Ui.MUTED);
            } else {
                fingerprintText.setText("SHA-256  " + fingerprint + "\n"
                        + KeyStoreManager.storageWarning());
                fingerprintText.setTextColor(Ui.RED);
            }
        } catch (Exception e) {
            fingerprintText.setText("SHA-256  unavailable");
            fingerprintText.setTextColor(Ui.RED);
        }
    }

    private void refresh() {
        if (statusText == null) return;
        boolean running = ServerRuntime.running;
        boolean error = !running && ServerRuntime.lastError != null;
        int dot;
        if (running) {
            dot = Ui.GREEN;
            statusText.setText(R.string.status_running);
            endpointText.setText("127.0.0.1:" + ServerRuntime.port
                    + "  \u2022  up " + formatUptime(ServerRuntime.uptimeMs()));
            Ui.setPill(statusPill, "ONLINE", Ui.GREEN, Ui.withAlpha(Ui.GREEN, 18), Ui.withAlpha(Ui.GREEN, 62));
            Ui.styleButton(this, startBtn, getString(R.string.btn_stop), Ui.KIND_DANGER, Ui.RED, false);
        } else if (error) {
            dot = Ui.RED;
            statusText.setText(R.string.status_error);
            endpointText.setText(ServerRuntime.lastError);
            Ui.setPill(statusPill, "ERROR", Ui.RED, Ui.withAlpha(Ui.RED, 18), Ui.withAlpha(Ui.RED, 62));
            Ui.styleButton(this, startBtn, getString(R.string.btn_start), Ui.KIND_PRIMARY, Ui.TEAL, false);
        } else {
            dot = Ui.FAINT;
            statusText.setText(R.string.status_stopped);
            endpointText.setText("127.0.0.1:" + ServerRuntime.PORT + "  \u2022  not running");
            Ui.setPill(statusPill, "OFFLINE", Ui.FAINT, Ui.withAlpha(Ui.FAINT, 18), Ui.BORDER);
            Ui.styleButton(this, startBtn, getString(R.string.btn_start), Ui.KIND_PRIMARY, Ui.TEAL, false);
        }
        ((GradientDrawable) statusDot.getBackground()).setColor(dot);

        int ready = 0;
        boolean granted = hasAllFilesAccess();
        if (granted) {
            ready++;
            permText.setText(R.string.perm_granted);
            permText.setTextColor(Ui.GREEN);
            Ui.styleButton(this, permBtn, "Manage", Ui.KIND_SECONDARY, Ui.TEAL, true);
        } else {
            permText.setText("Not granted \u2014 file access will fail");
            permText.setTextColor(Ui.RED);
            Ui.styleButton(this, permBtn, getString(R.string.btn_grant), Ui.KIND_PRIMARY, Ui.TEAL, true);
        }
        boolean notify = notificationsAllowed();
        if (notify) {
            ready++;
            notifyText.setText("Allowed");
            notifyText.setTextColor(Ui.GREEN);
            Ui.styleButton(this, notifyBtn, "Manage", Ui.KIND_SECONDARY, Ui.AMBER, true);
        } else {
            notifyText.setText("Blocked \u2014 status notification hidden");
            notifyText.setTextColor(Ui.AMBER);
            Ui.styleButton(this, notifyBtn, "Allow", Ui.KIND_PRIMARY, Ui.AMBER, true);
        }
        PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
        boolean exempt = power != null && power.isIgnoringBatteryOptimizations(getPackageName());
        if (exempt) {
            ready++;
            batteryText.setText("Unrestricted");
            batteryText.setTextColor(Ui.GREEN);
            Ui.styleButton(this, batteryBtn, "Manage", Ui.KIND_SECONDARY, Ui.VIOLET, true);
        } else {
            batteryText.setText("Optimized \u2014 server may be stopped");
            batteryText.setTextColor(Ui.AMBER);
            Ui.styleButton(this, batteryBtn, getString(R.string.btn_battery), Ui.KIND_PRIMARY, Ui.VIOLET, true);
        }
        if (ready == 3) {
            Ui.setPill(readinessCount, "READY", Ui.GREEN, Ui.withAlpha(Ui.GREEN, 18), Ui.withAlpha(Ui.GREEN, 62));
        } else {
            Ui.setPill(readinessCount, ready + "/3 SETUP", Ui.AMBER, Ui.withAlpha(Ui.AMBER, 18), Ui.withAlpha(Ui.AMBER, 62));
        }

        statsText.setText("requests " + ServerRuntime.requests.get()
                + "  \u2022  in " + human(ServerRuntime.bytesIn.get())
                + "  \u2022  out " + human(ServerRuntime.bytesOut.get())
                + "  \u2022  auth fails " + ServerRuntime.authFailures.get()
                + "\nlast  " + ServerRuntime.lastOp + "  " + shorten(ServerRuntime.lastPath, 34)
                + "  " + ServerRuntime.lastMs + " ms");
        updateClientViews();
        if (activePage == PAGE_AUDIT) updateAuditView();
    }

    private int lastClientCount = -1;

    private void updateClientViews() {
        if (clientsText == null) return;
        int count = PairStore.count(this);
        if (count == 0) {
            clientsText.setText(R.string.clients_none);
        } else if (count == 1) {
            clientsText.setText(R.string.clients_one);
        } else {
            clientsText.setText(getString(R.string.clients_many, count));
        }
        clientsCount.setText(String.valueOf(count));
        revokeClientsBtn.setVisibility(count == 0 ? View.GONE : View.VISIBLE);
        if (count == lastClientCount) return;
        lastClientCount = count;
        clientsContainer.removeAllViews();
        if (count == 0) {
            clientsContainer.addView(Ui.text(this, "No assistants paired yet.", 12f, Ui.FAINT, Ui.sans()));
            return;
        }
        SimpleDateFormat day = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
        for (PairStore.Client client : PairStore.list(this)) {
            LinearLayout row = row();
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(0, Ui.dp(this, 9), 0, Ui.dp(this, 9));
            row.addView(Ui.iconBox(this, R.drawable.ic_link, Ui.VIOLET, 32, 16),
                    new LinearLayout.LayoutParams(Ui.dp(this, 32), Ui.dp(this, 32)));
            LinearLayout copy = new LinearLayout(this);
            copy.setOrientation(LinearLayout.VERTICAL);
            copy.setPadding(Ui.dp(this, 11), 0, 0, 0);
            copy.addView(Ui.text(this, client.name, 13.5f, Ui.TEXT, Ui.sansMedium()));
            String fp = client.fingerprint == null ? "" : client.fingerprint;
            if (fp.length() > 16) fp = fp.substring(0, 16) + "\u2026";
            copy.addView(Ui.text(this, fp + (client.createdAt > 0 ? "  \u00b7  " + day.format(new Date(client.createdAt)) : ""),
                    10.5f, Ui.MUTED, Ui.mono()));
            row.addView(copy, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            clientsContainer.addView(row);
        }
    }

    private void updateAuditView() {
        if (auditText == null) return;
        String text = EventLog.snapshotText(80, clock);
        auditText.setText(text.length() == 0 ? "No events yet." : text);
        int lines = text.length() == 0 ? 0 : text.split("\n").length;
        auditSummary.setText(lines + " recent event(s) shown. Stored on this device only; "
                + "export writes JSONL to Download/Latchkey/logs.");
    }

    private boolean notificationsAllowed() {
        if (Build.VERSION.SDK_INT >= 33) {
            return checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                    == PackageManager.PERMISSION_GRANTED;
        }
        android.app.NotificationManager nm =
                (android.app.NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        return nm == null || nm.areNotificationsEnabled();
    }

    private void notificationAction() {
        EventLog.info("ui", "notifications", "notification settings requested");
        if (Build.VERSION.SDK_INT >= 33 && !notificationsAllowed()
                && !shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFICATIONS);
            return;
        }
        try {
            Intent intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Notification settings unavailable", Toast.LENGTH_SHORT).show();
        }
    }

    private void pairAssistant() {
        if (!ServerRuntime.running) {
            Toast.makeText(this, "Start the server first", Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            String link = PairingManager.createLink(this, appFingerprint(),
                    ServerRuntime.port);
            ClipboardManager clipboard =
                    (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) {
                Toast.makeText(this, "Clipboard unavailable", Toast.LENGTH_SHORT).show();
                return;
            }
            ClipData clip = ClipData.newPlainText("Latchkey pairing link", link);
            if (Build.VERSION.SDK_INT >= 33) {
                PersistableBundle extras = new PersistableBundle();
                extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
                clip.getDescription().setExtras(extras);
            }
            clipboard.setPrimaryClip(clip);
            pairHint.setText(R.string.pair_copied);
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    pairHint.setText(R.string.pair_hint);
                }
            }, 5000L);
            Toast.makeText(this, "Pairing link copied", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            String message = e.getMessage();
            if (message == null || message.length() == 0) {
                message = e.getClass().getSimpleName();
            }
            EventLog.error("pair", "link-failed", message);
            Toast.makeText(this, "Could not create pairing link",
                    Toast.LENGTH_LONG).show();
        }
    }

    private void confirmRevokeClients() {
        final int count = PairStore.count(this);
        if (count == 0) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Revoke paired assistants and rotate key?")
                .setMessage(count + (count == 1 ? " assistant" : " assistants")
                        + " will lose access immediately and the legacy key will be regenerated.")
                .setPositiveButton("Revoke & rotate", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        int revoked = PairManager.revokeAll(MainActivity.this);
                        String newKey = PairManager.regenerateKey(MainActivity.this);
                        EventLog.warn("key", "regenerate",
                                "access key regenerated from app revoke");
                        key = KeyStoreManager.getOrCreateKey(MainActivity.this);
                        updateKeyViews();
                        updateClientViews();
                        LatchkeyService.restart(MainActivity.this);
                        Toast.makeText(MainActivity.this,
                                "Revoked " + revoked + (revoked == 1 ? " assistant" : " assistants")
                                        + " · key rotated",
                                Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private String appFingerprint() {
        try {
            int flags = Build.VERSION.SDK_INT >= 28
                    ? PackageManager.GET_SIGNING_CERTIFICATES
                    : PackageManager.GET_SIGNATURES;
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), flags);
            Signature[] signatures = null;
            if (Build.VERSION.SDK_INT >= 28 && info.signingInfo != null) {
                signatures = info.signingInfo.getApkContentsSigners();
            } else if (info.signatures != null) {
                signatures = info.signatures;
            }
            if (signatures != null && signatures.length > 0) {
                return Crypto.fingerprint(signatures[0].toByteArray());
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    private void showLog() {
        String text = EventLog.snapshotText(500, clock);
        if (text.length() == 0) {
            text = "No activity yet.";
        }
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextIsSelectable(true);
        view.setTypeface(Typeface.MONOSPACE);
        view.setTextSize(11);
        int padding = dp(16);
        view.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(view);
        new AlertDialog.Builder(this)
                .setTitle("Activity log (last 500)")
                .setView(scroll)
                .setPositiveButton("Close", null)
                .show();
        EventLog.info("log", "view", "recent activity log viewed");
    }

    private void exportLog() {
        final File directory = new File(
                Environment.getExternalStorageDirectory(), "Download/Latchkey/logs");
        final String name = "latchkey-events-"
                + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date())
                + ".jsonl";
        final File destination = new File(directory, name);
        EventLog.info("log", "export", "activity log export requested");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    long bytes = EventLog.exportTo(destination);
                    EventLog.info("log", "exported", bytes + " bytes exported",
                            Json.put(Json.obj(), "path", destination.getAbsolutePath()));
                    final String message = "Exported " + human(bytes) + " to "
                            + destination.getAbsolutePath();
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this, message,
                                    Toast.LENGTH_LONG).show();
                        }
                    });
                } catch (final Exception e) {
                    String message = e.getMessage();
                    if (message == null || message.length() == 0) {
                        message = e.getClass().getSimpleName();
                    }
                    EventLog.error("log", "export-failed", message);
                    final String text = message;
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this,
                                    "Export failed: " + text, Toast.LENGTH_LONG).show();
                        }
                    });
                }
            }
        }, "latchkey-log-export").start();
    }

    private void clearLog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.clear_log_title)
                .setMessage(R.string.clear_log_message)
                .setPositiveButton(R.string.btn_clear_log,
                        new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            JSONObject cleared = EventLog.clear();
                                            int files = cleared.optInt("files", 0);
                                            long bytes = cleared.optLong("bytes", 0L);
                                            final String message = "Cleared " + files
                                                    + " log file(s), " + human(bytes);
                                            runOnUiThread(new Runnable() {
                                                @Override
                                                public void run() {
                                                    Toast.makeText(MainActivity.this,
                                                            message, Toast.LENGTH_SHORT).show();
                                                }
                                            });
                                        } catch (final Exception e) {
                                            String message = e.getMessage();
                                            if (message == null || message.length() == 0) {
                                                message = e.getClass().getSimpleName();
                                            }
                                            EventLog.error("log", "clear-failed", message);
                                            final String text = message;
                                            runOnUiThread(new Runnable() {
                                                @Override
                                                public void run() {
                                                    Toast.makeText(MainActivity.this,
                                                            "Clear failed: " + text,
                                                            Toast.LENGTH_LONG).show();
                                                }
                                            });
                                        }
                                    }
                                }, "latchkey-log-clear").start();
                            }
                        })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startServer() {
        EventLog.info("ui", "start", "start requested from activity");
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    REQ_NOTIFICATIONS);
        }
        if (!hasAllFilesAccess()) {
            EventLog.warn("permission", "missing", "all-files access is not granted");
            Toast.makeText(this, "Grant all-files access for file reads and writes",
                    Toast.LENGTH_LONG).show();
        }
        LatchkeyService.start(this);
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                refresh();
            }
        }, 600L);
    }

    private void copyKey() {
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) {
            Toast.makeText(this, "Clipboard unavailable", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipData clip = ClipData.newPlainText("Latchkey access key", key);
        if (Build.VERSION.SDK_INT >= 33) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        clipboard.setPrimaryClip(clip);
        EventLog.info("key", "copy", "access key copied to clipboard");
        Toast.makeText(this, "Key copied", Toast.LENGTH_SHORT).show();
    }

    private void confirmRegenerate() {
        new AlertDialog.Builder(this)
                .setTitle("Generate a new key?")
                .setMessage("The legacy key stops working immediately. "
                        + "Paired assistants keep access until you revoke them. "
                        + "The server will restart with the new key.")
                .setPositiveButton("New key", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        boolean wasRunning = ServerRuntime.running;
                        key = KeyStoreManager.regenerate(MainActivity.this);
                        keyVisible = false;
                        updateKeyViews();
                        if (wasRunning) {
                            EventLog.warn("key", "restart", "restarting server after key change");
                            LatchkeyService.restart(MainActivity.this);
                        }
                        handler.postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                refresh();
                            }
                        }, 700L);
                        Toast.makeText(MainActivity.this, "New key generated",
                                Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void openAllFilesSettings() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                Intent intent = new Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName()));
                startActivity(intent);
                return;
            } catch (Exception ignored) {
            }
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                return;
            } catch (Exception ignored) {
            }
        }
        requestPermissions(new String[]{
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
        }, REQ_STORAGE);
    }

    private void requestBatteryExemption() {
        PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (power != null && power.isIgnoringBatteryOptimizations(getPackageName())) {
            EventLog.info("battery", "already-exempt", "battery optimization already disabled");
            Toast.makeText(this, "Battery optimization already disabled",
                    Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            Intent intent = new Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception first) {
            try {
                startActivity(new Intent(
                        Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
            } catch (Exception second) {
                EventLog.warn("battery", "unavailable", "battery settings unavailable");
                Toast.makeText(this, "Battery settings unavailable",
                        Toast.LENGTH_SHORT).show();
            }
        }
    }

    private boolean hasAllFilesAccess() {
        if (Build.VERSION.SDK_INT >= 30) {
            return Environment.isExternalStorageManager();
        }
        return checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        int granted = 0;
        for (int result : grantResults) {
            if (result == PackageManager.PERMISSION_GRANTED) {
                granted++;
            }
        }
        EventLog.info("permission", "result", "request=" + requestCode
                + " granted=" + granted + "/" + grantResults.length);
        refresh();
    }

    private static String shorten(String text, int max) {
        if (text == null) {
            return "";
        }
        if (text.length() <= max) {
            return text;
        }
        return "\u2026" + text.substring(text.length() - Math.max(0, max - 1));
    }

    private static String human(long bytes) {
        if (bytes < 1024L) {
            return bytes + " B";
        }
        double value = bytes / 1024.0;
        if (value < 1024.0) {
            return String.format(Locale.US, "%.1f KiB", value);
        }
        value /= 1024.0;
        if (value < 1024.0) {
            return String.format(Locale.US, "%.1f MiB", value);
        }
        value /= 1024.0;
        return String.format(Locale.US, "%.2f GiB", value);
    }

    private static String formatUptime(long ms) {
        long seconds = ms / 1000L;
        if (seconds < 60L) {
            return seconds + "s";
        }
        long minutes = seconds / 60L;
        if (minutes < 60L) {
            return minutes + "m " + (seconds % 60L) + "s";
        }
        long hours = minutes / 60L;
        return hours + "h " + (minutes % 60L) + "m";
    }


    private int dp(int value) {
        return Ui.dp(this, value);
    }

    private static final class Page {
        final ScrollView scroll;
        final LinearLayout body;

        Page(ScrollView scroll, LinearLayout body) {
            this.scroll = scroll;
            this.body = body;
        }
    }

    private static final class ReadinessRow {
        final TextView state;
        final Button action;

        ReadinessRow(TextView state, Button action) {
            this.state = state;
            this.action = action;
        }
    }

    private static final class NavBinding {
        final View container;
        final ImageView icon;
        final TextView label;
        final int page;

        NavBinding(View container, ImageView icon, TextView label, int page) {
            this.container = container;
            this.icon = icon;
            this.label = label;
            this.page = page;
        }
    }
}
