package net.theavalanche.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.drawable.BitmapDrawable
import android.text.Editable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextWatcher
import android.text.style.ImageSpan
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.TextView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.core.graphics.TypefaceCompat

// ---------------------------------------------------------------------------
// RecipientTokenField — iMessage-style recipient pill field.
//
// Mirrors iOS Sources/Views/Chats/RecipientTokenField.swift.
//
// On iOS the chips are NSTextAttachments embedded in a UITextView so they
// behave as characters (backspace, selection all work natively). We mirror
// this on Android using ImageSpan inside an EditText — the chip IS a
// character (the Unicode object-replacement character U+FFFC), so all of the
// same backspace / selection semantics come for free.
//
// Public API surface:
//   - data class Chip  (id, did, displayName, label)
//   - class RecipientFieldHandle  (addChip)
//   - fun RecipientTokenField(chips, query, prefix, placeholder, handle, onSubmit, modifier)
//   - fun shortenDid(did)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Chip
// ---------------------------------------------------------------------------

/**
 * A confirmed recipient shown as a rounded pill in the [RecipientTokenField].
 *
 * Mirrors iOS `ComposeMessageView.Chip`.
 */
data class Chip(
    val id: String,       // == did
    val did: String,
    val displayName: String,
) {
    /** User-visible text for the chip. Never a raw full DID. */
    val label: String get() = if (displayName.isEmpty()) shortenDid(did) else displayName
}

// ---------------------------------------------------------------------------
// RecipientFieldHandle
// ---------------------------------------------------------------------------

/**
 * Lets Compose push a new chip into the [RecipientTokenEditText] without
 * owning its content. The field registers itself here when constructed.
 *
 * Mirrors iOS `RecipientFieldHandle`.
 */
class RecipientFieldHandle {
    // The field registers itself here; nullable because the view may not be
    // attached yet (or may have been recycled).
    internal var editText: RecipientTokenEditText? = null

    fun addChip(chip: Chip) {
        editText?.insertChip(chip)
    }

    /** Focus the field and raise the soft keyboard (compose keeps it up). */
    fun focusAndShowKeyboard() {
        editText?.focusAndShowKeyboard()
    }
}

// ---------------------------------------------------------------------------
// RecipientTokenEditText
// ---------------------------------------------------------------------------

/**
 * [EditText] whose recipients are rendered as [ImageSpan] pill chips.
 *
 * Chips are encoded as the Unicode OBJECT REPLACEMENT CHARACTER (U+FFFC),
 * tagged with a [ChipSpan] so they can be identified and extracted. Text
 * after the last chip is the "query" the user is currently typing.
 *
 * Mirrors iOS `RecipientTokenTextView`.
 */
class RecipientTokenEditText(context: Context) : EditText(context) {

    var onChipsChanged: ((List<Chip>) -> Unit)? = null
    var onQueryChanged: ((String) -> Unit)? = null
    var onSubmit: (() -> Unit)? = null

    private var suppressTextWatcher = false

    init {
        isSingleLine = false
        maxLines = Int.MAX_VALUE
        imeOptions = EditorInfo.IME_FLAG_NO_ENTER_ACTION
        inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        background = null
        textSize = 16f // sp — matches the Compose body size used around it

        val density = resources.displayMetrics.density
        setPadding(0, (8 * density).toInt(), 0, (8 * density).toInt())

        // Pin every line to the chip-line height so the field doesn't change
        // height (and shove the layout around) between empty / typed-text /
        // has-chips states: a chip line is text height + 2×3dp pill padding,
        // so make ALL lines that tall up front.
        val fm = paint.fontMetrics
        val chipLineHeight = ((fm.descent - fm.ascent) + 6 * density).toInt()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            lineHeight = chipLineHeight
        } else {
            val extra = chipLineHeight - (fm.descent - fm.ascent)
            setLineSpacing(extra, 1f)
        }

        // Palette (resolved from the View's night-mode config — not a
        // Composable, so it can't read LocalAvalancheColors): ink text, muted
        // hint. Without these the EditText inherits Activity-theme defaults,
        // which are wrong in dark mode.
        val sem = avalancheSemanticColors(context)
        setTextColor(sem.ink.toArgb())
        setHintTextColor(sem.muted.toArgb())

        // Brand tint for the text-selection highlight (all APIs) and the caret
        // (API 29+ via the textCursorDrawable setter; older devices fall back to
        // the platform accent color). Kept subtle — chip selection is shown by
        // swapping the pill to its inverted state (see onSelectionChanged), so
        // the rectangle is a secondary cue, not the selection UI itself.
        highlightColor = sem.brand.copy(alpha = 0.15f).toArgb()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            textCursorDrawable?.mutate()?.let { caret ->
                caret.setTint(avalancheSemanticColors(context).brand.toArgb())
                textCursorDrawable = caret
            }
        }

        addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (suppressTextWatcher) return
                val newChips = currentChips
                val newQuery = currentQuery
                onChipsChanged?.invoke(newChips)
                onQueryChanged?.invoke(newQuery)
            }
        })

        // Handle Enter → submit, and two-stage backspace.
        setOnKeyListener { _, keyCode, event ->
            if (event.action == KeyEvent.ACTION_DOWN && keyCode == KeyEvent.KEYCODE_ENTER) {
                onSubmit?.invoke()
                true
            } else {
                false
            }
        }

        // EditorActionListener as a safety net for software keyboards that send
        // IME_ACTION_DONE / IME_ACTION_NEXT instead of a key event.
        setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE ||
                actionId == EditorInfo.IME_ACTION_NEXT ||
                actionId == EditorInfo.IME_ACTION_SEND
            ) {
                onSubmit?.invoke()
                true
            } else {
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // Two-stage backspace: first backspace after a chip selects it; second
    // backspace (now a selection) deletes it — exactly matching iOS behaviour.
    // -----------------------------------------------------------------------

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        if (keyCode == KeyEvent.KEYCODE_DEL) {
            val sel = selectionStart
            if (selectionStart == selectionEnd && sel > 0) {
                val s = text ?: return super.onKeyDown(keyCode, event)
                val spans = s.getSpans(sel - 1, sel, ChipSpan::class.java)
                if (spans.isNotEmpty()) {
                    // Chip sits right before the cursor — select it instead of deleting.
                    setSelection(sel - 1, sel)
                    return true
                }
            }
        }
        return super.onKeyDown(keyCode, event)
    }

    // -----------------------------------------------------------------------
    // Selected-chip rendering: a selected chip redraws as its inverted pill
    // (solid brand fill, white text — the iOS selected-token look) instead of
    // relying on the translucent selection rectangle, which overlaps the pill
    // poorly (it covers the full line box and the pill's trailing gap).
    // -----------------------------------------------------------------------

    override fun onSelectionChanged(selStart: Int, selEnd: Int) {
        super.onSelectionChanged(selStart, selEnd)
        val s = text ?: return
        val spans = s.getSpans(0, s.length, ChipSpan::class.java)
        for (span in spans) {
            val start = s.getSpanStart(span)
            val end = s.getSpanEnd(span)
            if (start < 0) continue
            val selected = selStart != selEnd && start >= selStart && end <= selEnd
            if (span.selected != selected) {
                // Restyle in place: swap the span for one carrying the other
                // pill bitmap at the same range. Watcher suppressed — the
                // chip set hasn't changed, only its look.
                suppressTextWatcher = true
                try {
                    s.removeSpan(span)
                    val bitmap = renderChipBitmap(span.chip.label, selected)
                    val drawable = BitmapDrawable(resources, bitmap).apply {
                        setBounds(0, 0, bitmap.width, bitmap.height)
                    }
                    s.setSpan(
                        ChipSpan(drawable, span.chip, selected),
                        start,
                        end,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                    )
                } finally {
                    suppressTextWatcher = false
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Reading state
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Tap-to-select: tapping a chip selects it (which renders it inverted via
    // onSelectionChanged) — matching iOS, where a tap on a token selects it.
    // The default EditText tap just parks the caret next to the chip.
    // -----------------------------------------------------------------------

    private var touchDownX = 0f
    private var touchDownY = 0f

    override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
        when (event.actionMasked) {
            android.view.MotionEvent.ACTION_DOWN -> {
                touchDownX = event.x
                touchDownY = event.y
            }
            android.view.MotionEvent.ACTION_UP -> {
                val slop = android.view.ViewConfiguration.get(context).scaledTouchSlop
                val isTap = kotlin.math.abs(event.x - touchDownX) <= slop &&
                    kotlin.math.abs(event.y - touchDownY) <= slop
                if (isTap) {
                    val result = super.onTouchEvent(event) // caret placement, focus, IME
                    val s = text
                    if (s != null) {
                        val offset = getOffsetForPosition(event.x, event.y)
                        val span = s.getSpans(offset, offset, ChipSpan::class.java).firstOrNull()
                            ?: if (offset > 0) {
                                s.getSpans(offset - 1, offset, ChipSpan::class.java).firstOrNull()
                            } else {
                                null
                            }
                        if (span != null) {
                            val start = s.getSpanStart(span)
                            val end = s.getSpanEnd(span)
                            // Post so it lands after super's own caret move.
                            post { setSelection(start, end) }
                        }
                    }
                    return result
                }
            }
        }
        return super.onTouchEvent(event)
    }

    /**
     * Focus + raise the IME. `requestFocus()` alone doesn't show the keyboard
     * for a view inside Compose's AndroidView — the explicit
     * [InputMethodManager.showSoftInput] is required, posted so it runs after
     * focus/layout settles.
     */
    fun focusAndShowKeyboard() {
        requestFocus()
        post {
            val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
            imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
        }
    }

    val currentChips: List<Chip>
        get() {
            val s = text ?: return emptyList()
            return s.getSpans(0, s.length, ChipSpan::class.java)
                .sortedBy { s.getSpanStart(it) }
                .map { it.chip }
        }

    /** Text after the last chip — what the user is currently typing. */
    val currentQuery: String
        get() {
            val s = text ?: return ""
            val spans = s.getSpans(0, s.length, ChipSpan::class.java)
            val end = if (spans.isEmpty()) 0
            else spans.maxOf { s.getSpanEnd(it) }
            return s.substring(end)
        }

    // -----------------------------------------------------------------------
    // Mutation
    // -----------------------------------------------------------------------

    /** Replace all content with the given chips (used to seed the field). */
    fun setChips(chips: List<Chip>) {
        suppressTextWatcher = true
        try {
            val ssb = SpannableStringBuilder()
            for (chip in chips) ssb.appendChip(chip)
            setText(ssb)
            setSelection(length())
        } finally {
            suppressTextWatcher = false
        }
    }

    /**
     * Append a chip after the last chip, clearing any in-progress typed query.
     * No-op (beyond clearing the query) if the recipient is already present.
     */
    fun insertChip(chip: Chip) {
        val s = text ?: return
        // Remove any trailing query text (text after the last chip).
        val spans = s.getSpans(0, s.length, ChipSpan::class.java)
        val trailingStart = if (spans.isEmpty()) 0
        else spans.maxOf { s.getSpanEnd(it) }
        if (trailingStart < s.length) s.delete(trailingStart, s.length)

        val alreadyPresent = currentChips.any { it.did == chip.did }
        if (!alreadyPresent) {
            suppressTextWatcher = true
            try {
                s.appendChip(chip)
            } finally {
                suppressTextWatcher = false
            }
        }

        setSelection(length())
        // Notify observers manually (watcher was suppressed).
        onChipsChanged?.invoke(currentChips)
        onQueryChanged?.invoke(currentQuery)
    }

    // -----------------------------------------------------------------------
    // Chip rendering
    // -----------------------------------------------------------------------

    private fun Editable.appendChip(chip: Chip) {
        val bitmap = renderChipBitmap(chip.label)
        val drawable = BitmapDrawable(resources, bitmap).apply {
            setBounds(0, 0, bitmap.width, bitmap.height)
        }
        val span = ChipSpan(drawable, chip)
        val start = length
        append(CHIP_CHAR)
        setSpan(span, start, start + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    private fun SpannableStringBuilder.appendChip(chip: Chip) {
        val bitmap = renderChipBitmap(chip.label)
        val drawable = BitmapDrawable(resources, bitmap).apply {
            setBounds(0, 0, bitmap.width, bitmap.height)
        }
        val span = ChipSpan(drawable, chip)
        val start = length
        append(CHIP_CHAR)
        setSpan(span, start, start + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    /**
     * Render a chip pill bitmap with the same geometry as iOS:
     * hPad=9dp, vPad=3dp, trailing gap=6dp, cornerRadius = height/2.
     * Normal state: brand fill at 15% opacity, Ink text.
     * Selected state: solid brand fill, white text (the iOS selected-token
     * look) — swapped in by [onSelectionChanged].
     */
    internal fun renderChipBitmap(label: String, selected: Boolean = false): Bitmap {
        val density = resources.displayMetrics.density
        val hPad = (9 * density)
        val vPad = (3 * density)
        val trailingGap = (6 * density)
        // Resolved from the View's night-mode config (this is not a Composable, so
        // it can't read LocalAvalancheColors); the Activity is recreated on a
        // light/dark toggle so chips re-render with the right palette.
        val sem = avalancheSemanticColors(context)

        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            // Use the EditText's current text paint size for consistency.
            textSize = this@RecipientTokenEditText.paint.textSize
        }

        val textWidth = textPaint.measureText(label)
        val fm = textPaint.fontMetrics
        val textHeight = fm.descent - fm.ascent

        val pillWidth = textWidth + hPad * 2
        val pillHeight = textHeight + vPad * 2
        val totalWidth = pillWidth + trailingGap

        val bmp = Bitmap.createBitmap(
            totalWidth.toInt().coerceAtLeast(1),
            pillHeight.toInt().coerceAtLeast(1),
            Bitmap.Config.ARGB_8888,
        )
        val canvas = Canvas(bmp)

        val brandColor = sem.brand.toArgb()
        val bgColor = if (selected) {
            brandColor
        } else {
            android.graphics.Color.argb(
                (0.15f * 255).toInt(),
                android.graphics.Color.red(brandColor),
                android.graphics.Color.green(brandColor),
                android.graphics.Color.blue(brandColor),
            )
        }

        val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = bgColor }
        val pill = RectF(0f, 0f, pillWidth, pillHeight)
        canvas.drawRoundRect(pill, pillHeight / 2, pillHeight / 2, fillPaint)

        // Draw label text centered in the pill.
        val textX = hPad
        val textY = vPad - fm.ascent
        textPaint.color = if (selected) android.graphics.Color.WHITE else sem.ink.toArgb()
        canvas.drawText(label, textX, textY, textPaint)

        return bmp
    }

    companion object {
        /** Unicode OBJECT REPLACEMENT CHARACTER — the "character" for each chip. */
        const val CHIP_CHAR = '￼'
    }
}

// ---------------------------------------------------------------------------
// ChipSpan
// ---------------------------------------------------------------------------

/**
 * Tags a chip character with its [Chip] data so we can extract recipients
 * back out of the [Editable]. Extends [ImageSpan] so the pill bitmap is
 * drawn in-line, exactly as [NSTextAttachment] does on iOS.
 *
 * Vertically **centers** the pill on the text line (stock `ALIGN_BASELINE`
 * puts the pill's bottom on the baseline, floating it high above neighboring
 * text — the "poorly overlapping selection" look). Centering also keeps the
 * line box symmetric around the text so the selection rectangle hugs the pill.
 */
class ChipSpan(
    drawable: android.graphics.drawable.Drawable,
    val chip: Chip,
    val selected: Boolean = false,
) : ImageSpan(drawable, ALIGN_BASELINE) {

    override fun getSize(
        paint: Paint,
        text: CharSequence?,
        start: Int,
        end: Int,
        fm: Paint.FontMetricsInt?,
    ): Int {
        // Deliberately do NOT expand the line metrics to the pill height: the
        // EditText already pins every line to pill height via setLineHeight
        // (font line + spacing), and inflating fm here would ADD the pill
        // overhead on top of that spacing — making chip lines ~6dp taller
        // than text lines (a visible field-height jump when the first chip
        // lands). The pill instead draws centered, overflowing the font box
        // ~3dp into the reserved line spacing.
        if (fm != null) {
            val pfm = paint.fontMetricsInt
            fm.ascent = pfm.ascent
            fm.top = pfm.top
            fm.descent = pfm.descent
            fm.bottom = pfm.bottom
        }
        return drawable.bounds.width()
    }

    override fun draw(
        canvas: Canvas,
        text: CharSequence?,
        start: Int,
        end: Int,
        x: Float,
        top: Int,
        y: Int,
        bottom: Int,
        paint: Paint,
    ) {
        val d = drawable
        val pfm = paint.fontMetricsInt
        val fontCenter = y + (pfm.ascent + pfm.descent) / 2
        val transY = fontCenter - d.bounds.height() / 2
        canvas.save()
        canvas.translate(x, transY.toFloat())
        d.draw(canvas)
        canvas.restore()
    }
}

// ---------------------------------------------------------------------------
// RecipientTokenField Composable
// ---------------------------------------------------------------------------

/**
 * iMessage-style recipient token field backed by [RecipientTokenEditText].
 *
 * Mirrors iOS `RecipientTokenField` (a `UIViewRepresentable`). The chips and
 * query are reported back via [onChipsChanged] / [onQueryChanged]; new chips
 * can be pushed in programmatically via [handle].
 *
 * @param chips         Current list of recipient chips (read-only; use [handle] to add).
 * @param query         Current typed text (the search query following the chips).
 * @param prefix        Inline label before the first line (e.g. "To:").
 * @param placeholder   Hint text shown when the field is empty.
 * @param handle        Imperative handle for pushing chips in from autocomplete.
 * @param onChipsChanged Called when the chip list changes (chip removed by backspace, etc.).
 * @param onQueryChanged Called when the trailing text changes.
 * @param onSubmit      Called when the user presses Enter/Done.
 * @param modifier      Standard Compose modifier.
 */
@Composable
fun RecipientTokenField(
    chips: List<Chip>,
    query: String,
    prefix: String = "",
    placeholder: String = "",
    handle: RecipientFieldHandle,
    onChipsChanged: (List<Chip>) -> Unit = {},
    onQueryChanged: (String) -> Unit = {},
    onSubmit: () -> Unit = {},
    /**
     * Reports the field's first-line metrics in px, measured post-layout:
     * (baseline from view top, first-line vertical center from view top).
     * Compose siblings (the "To:" label, the add button) align to these real
     * values instead of guessed paddings — AndroidView does not propagate a
     * View's baseline to Compose's alignment-line system.
     */
    onFirstLineMetrics: ((baselinePx: Int, centerPx: Int) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    // We keep a reference to the underlying EditText so we can update prefix /
    // placeholder when Compose recomposes without re-creating the view.
    val editTextRef = remember { mutableListOf<RecipientTokenEditText>() }

    fun reportMetrics(et: RecipientTokenEditText) {
        val cb = onFirstLineMetrics ?: return
        et.post {
            // baseline is valid only after layout; lineHeight is fixed in init.
            if (et.baseline >= 0) {
                cb(et.baseline, et.paddingTop + et.lineHeight / 2)
            }
        }
    }

    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            RecipientTokenEditText(ctx).also { et ->
                et.hint = buildPrefixedHint(prefix, placeholder)
                et.onChipsChanged = onChipsChanged
                et.onQueryChanged = onQueryChanged
                et.onSubmit = onSubmit
                et.setChips(chips)
                handle.editText = et

                // Auto-focus the field AND raise the keyboard when it first
                // appears, mirroring iOS `didMoveToWindow` auto-focus.
                et.focusAndShowKeyboard()

                editTextRef.clear()
                editTextRef.add(et)
                reportMetrics(et)
            }
        },
        update = { et ->
            // Update prefix / placeholder on recomposition. Do NOT overwrite
            // the chip content — the view owns it, matching the iOS design.
            val newHint = buildPrefixedHint(prefix, placeholder)
            if (et.hint?.toString() != newHint) et.hint = newHint
            // Ensure the handle is wired (survives configuration changes).
            handle.editText = et
            reportMetrics(et)
        },
    )
}

/**
 * Build a hint string combining the optional [prefix] (e.g. "To: ") with
 * the [placeholder]. Android's hint is a single string; we concatenate them
 * with a space separator to approximate the iOS layout where the prefix
 * label sits inline and the placeholder follows it.
 *
 * NOTE: A full-fidelity prefix (label floated to the left, chips indented on the
 * first line only) would require a custom `Layout`/`StaticLayout` with exclusion
 * rects. We deliberately keep the simpler concatenated-hint approach: the active
 * composer (ComposeMessageView.RecipientFieldRow) renders the "To:" label as a
 * separate composable in its FlowRow, so this EditText-based variant does not need
 * the inline prefix.
 */
private fun buildPrefixedHint(prefix: String, placeholder: String): String =
    if (prefix.isNotEmpty()) "$prefix $placeholder" else placeholder

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

// shortenDid lives in ComposeMessageView.kt (same package) — single definition shared across Chats.
