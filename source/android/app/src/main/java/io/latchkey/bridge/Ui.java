package io.latchkey.bridge;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

final class Ui {
    public static final int BG = Color.rgb(7, 11, 18);
    public static final int CARD = Color.rgb(15, 23, 36);
    public static final int CARD_DEEP = Color.rgb(10, 16, 27);
    public static final int BORDER = Color.rgb(31, 45, 63);
    public static final int TEXT = Color.rgb(242, 247, 252);
    public static final int MUTED = Color.rgb(139, 156, 177);
    public static final int FAINT = Color.rgb(95, 112, 133);
    public static final int TEAL = Color.rgb(45, 212, 191);
    public static final int TEAL_DEEP = Color.rgb(13, 148, 136);
    public static final int VIOLET = Color.rgb(155, 124, 255);
    public static final int VIOLET_DEEP = Color.rgb(76, 53, 132);
    public static final int AMBER = Color.rgb(251, 191, 36);
    public static final int RED = Color.rgb(248, 113, 113);
    public static final int GREEN = Color.rgb(52, 211, 153);

    public static final int KIND_PRIMARY = 0;
    public static final int KIND_SECONDARY = 1;
    public static final int KIND_DANGER = 2;
    public static final int KIND_MUTED = 3;

    private Ui() {
    }

    public static int dp(Context context, float value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    public static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    public static Typeface sans() {
        return Typeface.create("sans-serif", Typeface.NORMAL);
    }

    public static Typeface sansMedium() {
        return Typeface.create("sans-serif-medium", Typeface.NORMAL);
    }

    public static Typeface sansBold() {
        return Typeface.create("sans-serif", Typeface.BOLD);
    }

    public static Typeface mono() {
        return Typeface.MONOSPACE;
    }

    public static TextView text(Context context, CharSequence value, float size, int color, Typeface face) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(face);
        view.setIncludeFontPadding(false);
        return view;
    }

    public static TextView section(Context context, String value) {
        TextView view = text(context, value, 11f, FAINT, sansMedium());
        view.setAllCaps(true);
        view.setLetterSpacing(0.14f);
        view.setPadding(0, 0, 0, dp(context, 10));
        return view;
    }

    public static TextView eyebrow(Context context, String value) {
        TextView view = text(context, value, 10.5f, MUTED, sansMedium());
        view.setAllCaps(true);
        view.setLetterSpacing(0.12f);
        return view;
    }

    public static GradientDrawable card(Context context, int fill, int stroke, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(context, radiusDp));
        if (Color.alpha(stroke) != 0) drawable.setStroke(dp(context, 1), stroke);
        return drawable;
    }

    public static GradientDrawable gradient(Context context, int top, int bottom, int stroke, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR, new int[] { top, bottom });
        drawable.setCornerRadius(dp(context, radiusDp));
        if (Color.alpha(stroke) != 0) drawable.setStroke(dp(context, 1), stroke);
        return drawable;
    }

    public static GradientDrawable inset(Context context, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(CARD_DEEP);
        drawable.setCornerRadius(dp(context, radiusDp));
        drawable.setStroke(dp(context, 1), BORDER);
        return drawable;
    }

    public static View circle(Context context, int color, int sizeDp) {
        View view = new View(context);
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(color);
        view.setBackground(drawable);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp));
        view.setLayoutParams(params);
        return view;
    }

    public static FrameLayout iconBox(Context context, int iconRes, int tint, int sizeDp, int iconDp) {
        FrameLayout box = new FrameLayout(context);
        GradientDrawable background = new GradientDrawable();
        background.setColor(withAlpha(tint, 28));
        background.setCornerRadius(dp(context, sizeDp / 3f));
        box.setBackground(background);
        box.setLayoutParams(new LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp)));
        ImageView icon = icon(context, iconRes, tint, iconDp);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                dp(context, iconDp), dp(context, iconDp), Gravity.CENTER);
        box.addView(icon, params);
        return box;
    }

    public static ImageView icon(Context context, int iconRes, int tint, int sizeDp) {
        ImageView view = new ImageView(context);
        view.setImageResource(iconRes);
        view.setColorFilter(tint);
        view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp)));
        return view;
    }

    public static TextView pill(Context context, String value, int foreground, int fill, int stroke) {
        TextView view = text(context, value, 10.5f, foreground, sansMedium());
        view.setGravity(Gravity.CENTER);
        view.setLetterSpacing(0.08f);
        view.setAllCaps(true);
        view.setPadding(dp(context, 9), dp(context, 5), dp(context, 9), dp(context, 5));
        view.setBackground(pillBackground(context, fill, stroke));
        view.setSingleLine(true);
        return view;
    }

    public static void setPill(TextView view, String value, int foreground, int fill, int stroke) {
        view.setText(value);
        view.setTextColor(foreground);
        view.setBackground(pillBackground(view.getContext(), fill, stroke));
    }

    private static GradientDrawable pillBackground(Context context, int fill, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(context, 99));
        if (Color.alpha(stroke) != 0) drawable.setStroke(dp(context, 1), stroke);
        return drawable;
    }

    public static Button button(Context context, String label, int kind, int accent) {
        return button(context, label, kind, accent, false);
    }

    public static Button button(Context context, String label, int kind, int accent, boolean compact) {
        Button button = new Button(context);
        applyButton(context, button, label, kind, accent, compact);
        return button;
    }

    public static void styleButton(Context context, Button button, String label, int kind, int accent, boolean compact) {
        applyButton(context, button, label, kind, accent, compact);
    }

    private static void applyButton(Context context, Button button, String label, int kind, int accent, boolean compact) {
        int fill;
        int stroke;
        int foreground;
        if (kind == KIND_PRIMARY) {
            fill = accent;
            stroke = accent;
            foreground = Color.rgb(4, 13, 16);
        } else if (kind == KIND_DANGER) {
            fill = Color.TRANSPARENT;
            stroke = RED;
            foreground = RED;
        } else if (kind == KIND_MUTED) {
            fill = Color.TRANSPARENT;
            stroke = BORDER;
            foreground = FAINT;
        } else {
            fill = Color.TRANSPARENT;
            stroke = accent;
            foreground = accent;
        }
        button.setText(label);
        button.setAllCaps(false);
        button.setTextSize(compact ? 12.5f : 14.5f);
        button.setTextColor(foreground);
        button.setTypeface(compact ? sansMedium() : sansBold());
        button.setGravity(Gravity.CENTER);
        button.setIncludeFontPadding(false);
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setMinHeight(dp(context, compact ? 38 : 48));
        button.setMinimumHeight(dp(context, compact ? 38 : 48));
        button.setPadding(dp(context, compact ? 12 : 16), 0, dp(context, compact ? 12 : 16), 0);
        button.setStateListAnimator(null);
        GradientDrawable content = card(context, fill, stroke, compact ? 11 : 14);
        button.setBackground(new RippleDrawable(
                ColorStateList.valueOf(withAlpha(accent, 54)), content, null));
    }

    public static View divider(Context context) {
        View view = new View(context);
        view.setBackgroundColor(BORDER);
        view.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(context, 1)));
        return view;
    }

    public static View space(Context context, int heightDp) {
        View view = new View(context);
        view.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(context, heightDp)));
        return view;
    }

    public static void margins(View view, int left, int top, int right, int bottom) {
        ViewGroup.LayoutParams raw = view.getLayoutParams();
        if (!(raw instanceof ViewGroup.MarginLayoutParams)) {
            raw = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        ViewGroup.MarginLayoutParams params = (ViewGroup.MarginLayoutParams) raw;
        Context context = view.getContext();
        params.setMargins(dp(context, left), dp(context, top), dp(context, right), dp(context, bottom));
        view.setLayoutParams(params);
    }

    public static int withAlpha(int color, int alpha) {
        return (color & 0x00FFFFFF) | ((alpha & 0xFF) << 24);
    }
}
