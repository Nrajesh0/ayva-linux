/*
 * Ayva for Fedora GNOME 44+
 * Smart Natural Language Date, Recurrence & Task Parser
 *
 * 1:1 Rust Port of Ayva's `SmartDateParser.kt` with desktop extensions:
 * - Natural language prefix stripping ("remind me to", "schedule", "task:", etc.)
 * - Relative and named days ("today", "tomorrow", "tonight", "next friday", "in 3 days")
 * - ISO, DMY, and month name dates ("Oct 15", "15th of January", "2026-10-15")
 * - Time parsing (AM/PM, 24-hr, "noon", "midnight", "morning", "9 o'clock")
 * - Recurrence rules (Daily, Weekly, Monthly, Yearly, Birthday/Anniversary auto-detect)
 * - Tag extraction ("#work", "#personal") and priority parsing ("!urgent", "!high", "p1")
 * - Leap year handling (Feb 29 -> Feb 28 graceful fallback in non-leap years)
 */

use chrono::{Datelike, Duration, Local, NaiveDate, NaiveDateTime, NaiveTime, Timelike};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecurrencePattern {
    None,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    None,
    Low,
    Medium,
    High,
    Urgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseResult {
    pub clean_text: String,
    pub timestamp: Option<i64>, // Milliseconds since Unix epoch
    pub has_time: bool,
    pub recurrence: RecurrencePattern,
    pub tags: Vec<String>,
    pub priority: Priority,
    pub note: Option<String>,
}

fn remove_range(source: &str, range: Range<usize>) -> String {
    let before = &source[..range.start];
    let after = &source[range.end..];
    let combined = format!("{} {}", before.trim(), after.trim());
    let whitespace_re = Regex::new(r"\s+").unwrap();
    whitespace_re.replace_all(combined.trim(), " ").to_string()
}

pub struct SmartDateParser;

impl SmartDateParser {
    pub fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    pub fn parse(input: &str) -> ParseResult {
        Self::parse_with_base(input, Local::now().naive_local())
    }

    pub fn parse_with_base(input: &str, now: NaiveDateTime) -> ParseResult {
        let mut text = input.trim().to_string();
        let mut target_date = now.date();
        let mut target_time: Option<NaiveTime> = None;

        let mut has_explicit_date = false;
        let mut has_explicit_time = false;
        let mut detected_recurrence = RecurrencePattern::None;
        let mut detected_note: Option<String> = None;
        let mut priority = Priority::None;
        let mut tags: Vec<String> = Vec::new();

        // --- Step 0A: Extract Priority Markers (!urgent, !high, !medium, !low, p1, p2, p3, p4) ---
        let priority_regex = Regex::new(r"(?i)(?:!(urgent|high|med|medium|low)\b|\bp([1-4])\b)").unwrap();
        if let Some(m) = priority_regex.find(&text) {
            let mat_str = m.as_str().to_lowercase();
            if mat_str.contains("urgent") || mat_str == "p1" {
                priority = Priority::Urgent;
            } else if mat_str.contains("high") || mat_str == "p2" {
                priority = Priority::High;
            } else if mat_str.contains("med") || mat_str == "p3" {
                priority = Priority::Medium;
            } else if mat_str.contains("low") || mat_str == "p4" {
                priority = Priority::Low;
            }
            text = remove_range(&text, m.range());
        }

        // --- Step 0B: Extract Hashtags (#work, #dev, #health) ---
        let tag_regex = Regex::new(r"(?i)#([a-zA-Z0-9_\-]+)").unwrap();
        for cap in tag_regex.captures_iter(&text.clone()) {
            if let Some(tag_match) = cap.get(1) {
                tags.push(tag_match.as_str().to_lowercase());
            }
        }
        text = tag_regex.replace_all(&text, "").trim().to_string();

        // --- Step 0C: Clean Command Prefixes ---
        let prefix_regex = Regex::new(r"(?i)^\s*(?:(?:please\s+)?(?:add|new|create|schedule)\s+(?:a\s+)?(?:task|todo|reminder|meeting)?(?:\s+to)?|schedule|task|todo|reminder|please\s+remind\s+me\s+to|remind\s+me\s+to|remember\s+to|need\s+to|i\s+need\s+to|have\s+to|i\s+have\s+to|must\b|don't\s+forget\s+to|reschedule(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|postpone(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|move(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|push(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|delay(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|bump(?:\s+(?:the|my)?\s*task)?(?:\s+to)?|change(?:\s+(?:the|my)?\s*(?:due\s+)?(?:date|time))?(?:\s+to)?|set(?:\s+(?:the|my)?\s*(?:due\s+)?(?:date|time))?(?:\s+to)?)\s*[,:\-]?\s*").unwrap();
        if let Some(m) = prefix_regex.find(&text) {
            text = remove_range(&text, m.range());
        }

        // --- Step 1: Recurrence Pattern Detection ---
        let monthly_regex = Regex::new(r"(?i)\b(?:of\s+every\s+month|every\s+month|each\s+month|monthly)\b").unwrap();
        if let Some(m) = monthly_regex.find(&text) {
            detected_recurrence = RecurrencePattern::Monthly;
            text = remove_range(&text, m.range());
        }

        let daily_regex = Regex::new(r"(?i)\b(?:every\s+day|each\s+day|daily|everyday)\b").unwrap();
        if let Some(m) = daily_regex.find(&text) {
            detected_recurrence = RecurrencePattern::Daily;
            text = remove_range(&text, m.range());
        }

        let weekly_regex = Regex::new(r"(?i)\b(?:every\s+week|each\s+week|weekly)\b").unwrap();
        if let Some(m) = weekly_regex.find(&text) {
            detected_recurrence = RecurrencePattern::Weekly;
            text = remove_range(&text, m.range());
        }

        let yearly_regex = Regex::new(r"(?i)\b(?:every\s+year|each\s+year|yearly|annually)\b").unwrap();
        if let Some(m) = yearly_regex.find(&text) {
            detected_recurrence = RecurrencePattern::Yearly;
            text = remove_range(&text, m.range());
        }

        // Auto-detect yearly recurrence for birthday/anniversary
        let birthday_regex = Regex::new(r"(?i)\b(?:birthday|anniversary|bday)\b").unwrap();
        if detected_recurrence == RecurrencePattern::None && birthday_regex.is_match(&text) {
            detected_recurrence = RecurrencePattern::Yearly;
        }

        let every_dow_regex = Regex::new(r"(?i)\b(?:every)\s+(mon|tue|wed|thu|fri|sat|sun)(?:day|nes)?(?:day)?\b").unwrap();
        if let Some(cap) = every_dow_regex.captures(&text) {
            detected_recurrence = RecurrencePattern::Weekly;
            let day_str = cap.get(1).unwrap().as_str().to_lowercase();
            let target_weekday = match day_str.as_str() {
                "sun" => chrono::Weekday::Sun,
                "mon" => chrono::Weekday::Mon,
                "tue" => chrono::Weekday::Tue,
                "wed" => chrono::Weekday::Wed,
                "thu" => chrono::Weekday::Thu,
                "fri" => chrono::Weekday::Fri,
                "sat" => chrono::Weekday::Sat,
                _ => chrono::Weekday::Mon,
            };
            let current_weekday = target_date.weekday();
            let mut diff = (target_weekday.num_days_from_monday() as i64)
                - (current_weekday.num_days_from_monday() as i64);
            if diff < 0 {
                diff += 7;
            }
            target_date += Duration::days(diff);
            has_explicit_date = true;
            let range = cap.get(0).unwrap().range();
            text = remove_range(&text, range);
        }

        // --- Step 2: "in X time" ---
        let in_regex = Regex::new(r"(?i)\b(in)\s+(\d+)\s+(m|min|mins|minutes?|h|hr|hrs|hours?|d|days?|w|wks|weeks?|mo|mos|months?|y|yr|yrs|years?)\b").unwrap();
        if let Some(cap) = in_regex.captures(&text) {
            let amount: i64 = cap.get(2).and_then(|a| a.as_str().parse().ok()).unwrap_or(0);
            let unit = cap.get(3).unwrap().as_str().to_lowercase();
            let range = cap.get(0).unwrap().range();

            if unit.starts_with("mo") || unit.contains("month") {
                target_date = add_months(target_date, amount as i32);
                has_explicit_date = true;
            } else if unit.starts_with('y') || unit.contains("year") {
                target_date = add_years(target_date, amount as i32);
                has_explicit_date = true;
            } else if unit.starts_with('m') {
                let new_dt = now + Duration::minutes(amount);
                target_date = new_dt.date();
                target_time = Some(new_dt.time());
                has_explicit_time = true;
                has_explicit_date = true;
            } else if unit.starts_with('h') {
                let new_dt = now + Duration::hours(amount);
                target_date = new_dt.date();
                target_time = Some(new_dt.time());
                has_explicit_time = true;
                has_explicit_date = true;
            } else if unit.starts_with('d') {
                target_date += Duration::days(amount);
                has_explicit_date = true;
            } else if unit.starts_with('w') {
                target_date += Duration::weeks(amount);
                has_explicit_date = true;
            }
            text = remove_range(&text, range);
        }

        // --- Step 3: Named Relative Days ("today", "tomorrow", "tmrw", "tmr", "tonight", "next week", "next month", "next year") ---
        if !has_explicit_date {
            let day_regex = Regex::new(r"(?i)\b(today|tomorrow|tmrw|tmr|tonight|next\s+week|next\s+month|next\s+year)\b").unwrap();
            if let Some(cap) = day_regex.captures(&text) {
                let word = cap.get(1).unwrap().as_str().to_lowercase();
                let range = cap.get(0).unwrap().range();
                if word == "tomorrow" || word == "tmrw" || word == "tmr" {
                    target_date += Duration::days(1);
                    has_explicit_date = true;
                } else if word == "tonight" {
                    target_time = Some(NaiveTime::from_hms_opt(20, 0, 0).unwrap());
                    has_explicit_time = true;
                    has_explicit_date = true;
                } else if word.contains("week") {
                    target_date += Duration::weeks(1);
                    has_explicit_date = true;
                } else if word.contains("month") {
                    target_date = add_months(target_date, 1);
                    has_explicit_date = true;
                } else if word.contains("year") {
                    target_date = add_years(target_date, 1);
                    has_explicit_date = true;
                } else if word == "today" {
                    has_explicit_date = true;
                }
                text = remove_range(&text, range);
            }
        }

        // --- Step 4: ISO & Numeric Dates ---
        if !has_explicit_date {
            let iso_regex = Regex::new(r"(?i)\b((?:19|20|21)\d{2})[-/.](0?[1-9]|1[0-2])[-/.](0?[1-9]|[12]\d|3[01])\b").unwrap();
            let dmy_regex = Regex::new(r"(?i)\b(?:on\s+)?(0?[1-9]|[12]\d|3[01])[-/](0?[1-9]|[12]\d|3[01])[-/]((?:19|20|21)\d{2})\b").unwrap();

            if let Some(cap) = iso_regex.captures(&text) {
                let y: i32 = cap.get(1).unwrap().as_str().parse().unwrap();
                let m: u32 = cap.get(2).unwrap().as_str().parse().unwrap();
                let d: u32 = cap.get(3).unwrap().as_str().parse().unwrap();
                let range = cap.get(0).unwrap().range();
                target_date = resolve_calendar_date(y, m, d, &mut detected_note);
                has_explicit_date = true;
                text = remove_range(&text, range);
            } else if let Some(cap) = dmy_regex.captures(&text) {
                let num1: u32 = cap.get(1).unwrap().as_str().parse().unwrap_or(1);
                let num2: u32 = cap.get(2).unwrap().as_str().parse().unwrap_or(1);
                let y: i32 = cap.get(3).unwrap().as_str().parse().unwrap();
                let range = cap.get(0).unwrap().range();

                let (m, d) = if num1 > 12 {
                    (num2, num1)
                } else {
                    (num1, num2)
                };
                target_date = resolve_calendar_date(y, m, d, &mut detected_note);
                has_explicit_date = true;
                text = remove_range(&text, range);
            }
        }

        // --- Step 5: Month + Day ("May 20", "20th of May", "Oct 15 2026") ---
        if !has_explicit_date {
            let month_names = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
            let month_regex = Regex::new(r"(?i)\b(?:on\s+)?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+(\d{1,2})(?:\s*(?:st|nd|rd|th))?(?:[\s,]+((?:19|20|21)\d{2}))?\b").unwrap();
            let day_month_regex = Regex::new(r"(?i)\b(?:on\s+)?(\d{1,2})(?:\s*(?:st|nd|rd|th))?\s+(?:of\s+)?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*(?:[\s,]+((?:19|20|21)\d{2}))?\b").unwrap();

            if let Some(cap) = month_regex.captures(&text) {
                let m_str = cap.get(1).unwrap().as_str().to_lowercase();
                let d: u32 = cap.get(2).unwrap().as_str().parse().unwrap_or(1);
                let y_opt = cap.get(3).and_then(|y| y.as_str().parse::<i32>().ok());
                let range = cap.get(0).unwrap().range();

                if let Some(idx) = month_names.iter().position(|&m| m == m_str) {
                    let m = (idx + 1) as u32;
                    let mut y = y_opt.unwrap_or_else(|| now.year());
                    if y_opt.is_none() {
                        let test_date = resolve_calendar_date(y, m, d, &mut None);
                        if test_date < now.date() {
                            y += 1;
                        }
                    }
                    target_date = resolve_calendar_date(y, m, d, &mut detected_note);
                    has_explicit_date = true;
                    text = remove_range(&text, range);
                }
            } else if let Some(cap) = day_month_regex.captures(&text) {
                let d: u32 = cap.get(1).unwrap().as_str().parse().unwrap_or(1);
                let m_str = cap.get(2).unwrap().as_str().to_lowercase();
                let y_opt = cap.get(3).and_then(|y| y.as_str().parse::<i32>().ok());
                let range = cap.get(0).unwrap().range();

                if let Some(idx) = month_names.iter().position(|&m| m == m_str) {
                    let m = (idx + 1) as u32;
                    let mut y = y_opt.unwrap_or_else(|| now.year());
                    if y_opt.is_none() {
                        let test_date = resolve_calendar_date(y, m, d, &mut None);
                        if test_date < now.date() {
                            y += 1;
                        }
                    }
                    target_date = resolve_calendar_date(y, m, d, &mut detected_note);
                    has_explicit_date = true;
                    text = remove_range(&text, range);
                }
            }
        }

        // --- Step 6: Day of Week ("on monday", "next friday", "this sunday") ---
        if !has_explicit_date {
            let dow_regex = Regex::new(r"(?i)\b(?:on\s+|next\s+|this\s+)?(mon|tue|wed|thu|fri|sat|sun)(?:day|nes)?(?:day)?\b").unwrap();
            if let Some(cap) = dow_regex.captures(&text) {
                let day_str = cap.get(1).unwrap().as_str().to_lowercase();
                let target_weekday = match day_str.as_str() {
                    "sun" => chrono::Weekday::Sun,
                    "mon" => chrono::Weekday::Mon,
                    "tue" => chrono::Weekday::Tue,
                    "wed" => chrono::Weekday::Wed,
                    "thu" => chrono::Weekday::Thu,
                    "fri" => chrono::Weekday::Fri,
                    "sat" => chrono::Weekday::Sat,
                    _ => chrono::Weekday::Mon,
                };
                let current_weekday = now.weekday();
                let mut diff = (target_weekday.num_days_from_monday() as i64)
                    - (current_weekday.num_days_from_monday() as i64);
                if diff <= 0 {
                    diff += 7;
                }
                if cap.get(0).unwrap().as_str().to_lowercase().contains("next") {
                    diff += 7;
                }
                target_date = now.date() + Duration::days(diff);
                has_explicit_date = true;
                let range = cap.get(0).unwrap().range();
                text = remove_range(&text, range);
            }
        }

        // --- Step 7: Ordinal Day ("15th", "on the 25th", "on 12") ---
        if !has_explicit_date {
            let ordinal_regex = Regex::new(r"(?i)\b(?:on\s+(?:the\s+)?|the\s+)?(\d{1,2})\s*(?:st|nd|rd|th)\b").unwrap();
            let strict_on_regex = Regex::new(r"(?i)\bon\s+(?:the\s+)?(\d{1,2})\b").unwrap();

            let match_data = if let Some(cap) = ordinal_regex.captures(&text) {
                Some((cap.get(1).unwrap().as_str().parse::<u32>().unwrap_or(1), cap.get(0).unwrap().range()))
            } else if let Some(cap) = strict_on_regex.captures(&text) {
                Some((cap.get(1).unwrap().as_str().parse::<u32>().unwrap_or(1), cap.get(0).unwrap().range()))
            } else {
                None
            };

            if let Some((d, range)) = match_data {
                if (1..=31).contains(&d) {
                    let mut m = now.month();
                    let mut y = now.year();
                    if d < now.day() {
                        m += 1;
                        if m > 12 {
                            m = 1;
                            y += 1;
                        }
                    }
                    target_date = resolve_calendar_date(y, m, d, &mut detected_note);
                    has_explicit_date = true;
                    text = remove_range(&text, range);
                }
            }
        }

        // --- Step 8: Time Parsing (AM/PM, HH:MM, at 5, noon, midnight, etc.) ---
        if !has_explicit_time {
            let time_ampm_regex = Regex::new(r"(?i)\b(?:at|by|to|for|around)?\s*(\d{1,2})(?:[:.](\d{1,2}))?\s*(am|pm)\b").unwrap();
            let time_sep_regex = Regex::new(r"(?i)\b(?:at|by|to|for|around)?\s*(\d{1,2})[:.](\d{2})\b").unwrap();
            let time_at_regex = Regex::new(r"(?i)\b(?:(?:at|by|to|for|around)\s+)?(\d{1,2})\s*o'?clock\b|\b(?:at|by|to|for|around)\s+(\d{1,2})\b").unwrap();
            let named_time_regex = Regex::new(r"(?i)\b(noon|midnight|in\s+the\s+morning|in\s+the\s+afternoon|in\s+the\s+evening|at\s+night|morning|afternoon|evening|tonight)\b").unwrap();

            if let Some(cap) = time_ampm_regex.captures(&text) {
                let mut hour: u32 = cap.get(1).unwrap().as_str().parse().unwrap_or(12);
                let minute: u32 = cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                let ampm = cap.get(3).unwrap().as_str().to_lowercase();
                let range = cap.get(0).unwrap().range();

                if ampm == "pm" && hour < 12 {
                    hour += 12;
                }
                if ampm == "am" && hour == 12 {
                    hour = 0;
                }

                if hour < 24 && minute < 60 {
                    target_time = NaiveTime::from_hms_opt(hour, minute, 0);
                    has_explicit_time = true;
                    text = remove_range(&text, range);
                }
            } else if let Some(cap) = time_sep_regex.captures(&text) {
                let mut hour: u32 = cap.get(1).unwrap().as_str().parse().unwrap_or(12);
                let minute: u32 = cap.get(2).unwrap().as_str().parse().unwrap_or(0);
                let range = cap.get(0).unwrap().range();

                if hour < 24 && minute < 60 {
                    let lower_text = text.to_lowercase();
                    let is_evening = lower_text.contains("evening") || lower_text.contains("night") || lower_text.contains("tonight");
                    let is_afternoon = lower_text.contains("afternoon");
                    let is_morning = lower_text.contains("morning");

                    if is_evening && (1..=11).contains(&hour) {
                        hour += 12;
                    } else if is_afternoon && (1..=6).contains(&hour) {
                        hour += 12;
                    } else if is_morning && hour == 12 {
                        hour = 0;
                    } else if !is_morning && (1..=7).contains(&hour) {
                        hour += 12;
                    }

                    target_time = NaiveTime::from_hms_opt(hour, minute, 0);
                    has_explicit_time = true;
                    text = remove_range(&text, range);
                }
            } else if let Some(cap) = time_at_regex.captures(&text) {
                let h1 = cap.get(1).and_then(|h| h.as_str().parse::<u32>().ok());
                let h2 = cap.get(2).and_then(|h| h.as_str().parse::<u32>().ok());
                let mut hour = h1.or(h2).unwrap_or(12);
                let range = cap.get(0).unwrap().range();

                if hour < 24 {
                    let lower_text = text.to_lowercase();
                    let is_evening = lower_text.contains("evening") || lower_text.contains("night") || lower_text.contains("tonight");
                    let is_afternoon = lower_text.contains("afternoon");
                    let is_morning = lower_text.contains("morning");

                    if is_evening && (1..=11).contains(&hour) {
                        hour += 12;
                    } else if is_afternoon && (1..=6).contains(&hour) {
                        hour += 12;
                    } else if !is_morning && (1..=7).contains(&hour) {
                        hour += 12;
                    }

                    target_time = NaiveTime::from_hms_opt(hour, 0, 0);
                    has_explicit_time = true;
                    text = remove_range(&text, range);
                }
            } else if let Some(cap) = named_time_regex.captures(&text) {
                let word = cap.get(1).unwrap().as_str().to_lowercase();
                let range = cap.get(0).unwrap().range();
                let h = match word.as_str() {
                    "noon" => 12,
                    "midnight" => 0,
                    w if w.contains("morning") => 9,
                    w if w.contains("afternoon") => 14,
                    w if w.contains("evening") => 18,
                    _ => 20,
                };
                target_time = NaiveTime::from_hms_opt(h, 0, 0);
                has_explicit_time = true;
                text = remove_range(&text, range);
            }
        }

        // Clean leftover time-of-day phrases
        let leftover_tod = Regex::new(r"(?i)\b(?:in\s+the\s+morning|in\s+the\s+afternoon|in\s+the\s+evening|at\s+night)\b").unwrap();
        if let Some(m) = leftover_tod.find(&text) {
            text = remove_range(&text, m.range());
        }

        // --- Step 9: Time Rollover Heuristic ---
        if has_explicit_time && !has_explicit_date {
            if let Some(t) = target_time {
                if NaiveDateTime::new(target_date, t) < now {
                    target_date += Duration::days(1);
                }
            }
            has_explicit_date = true;
        }

        // --- Step 10: Clean Leftover Punctuation & Prepositions ---
        let mut clean = text.trim().to_string();
        clean = Regex::new(r"^[,:\- ]+").unwrap().replace_all(&clean, "").to_string();
        clean = Regex::new(r"[,:\- ]+$").unwrap().replace_all(&clean, "").to_string();
        clean = Regex::new(r"(?i)\b(on|at|every|the|for|by|in|to|until)\s*$").unwrap().replace_all(&clean, "").to_string();
        clean = Regex::new(r"(?i)^\s*(on|at|every|the|for|by|in|to|until)\b").unwrap().replace_all(&clean, "").to_string();
        clean = Regex::new(r"^[,:\- ]+").unwrap().replace_all(&clean, "").to_string();
        clean = Regex::new(r"[,:\- ]+$").unwrap().replace_all(&clean, "").to_string();
        let whitespace_re = Regex::new(r"\s+").unwrap();
        clean = whitespace_re.replace_all(clean.trim(), " ").to_string();

        if clean.is_empty() {
            clean = input.trim().to_string();
        }

        // Default time assignment
        let final_time = if has_explicit_time {
            target_time.unwrap_or_else(|| NaiveTime::from_hms_opt(8, 0, 0).unwrap())
        } else if has_explicit_date {
            let is_today = target_date == now.date();
            if is_today && now.hour() >= 8 {
                let h = if now.hour() >= 21 { 23 } else { 21 };
                let m = if h == 23 { 59 } else { 0 };
                NaiveTime::from_hms_opt(h, m, 0).unwrap()
            } else {
                NaiveTime::from_hms_opt(8, 0, 0).unwrap()
            }
        } else {
            NaiveTime::from_hms_opt(8, 0, 0).unwrap()
        };

        // Determine final timestamp
        let timestamp_ms = if has_explicit_date {
            let dt = NaiveDateTime::new(target_date, final_time);
            Some(dt.and_utc().timestamp_millis())
        } else if detected_recurrence != RecurrencePattern::None {
            let mut dt = NaiveDateTime::new(target_date, final_time);
            if dt < now {
                dt += match detected_recurrence {
                    RecurrencePattern::Daily => Duration::days(1),
                    RecurrencePattern::Weekly => Duration::weeks(1),
                    RecurrencePattern::Monthly => Duration::days(30),
                    RecurrencePattern::Yearly => Duration::days(365),
                    RecurrencePattern::None => Duration::zero(),
                };
            }
            Some(dt.and_utc().timestamp_millis())
        } else {
            None
        };

        // Leap year detection note
        let feb29_regex = Regex::new(r"(?i)\b(?:feb(?:ruary)?\s*29(?:th)?|29(?:th)?\s*(?:of\s*)?feb(?:ruary)?)\b").unwrap();
        if detected_note.is_none() && feb29_regex.is_match(input) {
            let y = target_date.year();
            detected_note = Some(if Self::is_leap_year(y) {
                "Note: Event is on Feb 29th".to_string()
            } else {
                "Note: Event is on Feb 29th (reminded on Feb 28th in non-leap years)".to_string()
            });
        }

        ParseResult {
            clean_text: clean,
            timestamp: timestamp_ms,
            has_time: has_explicit_time,
            recurrence: detected_recurrence,
            tags,
            priority,
            note: detected_note,
        }
    }
}

fn add_months(date: NaiveDate, months: i32) -> NaiveDate {
    let mut year = date.year();
    let mut month = date.month() as i32 + months;
    while month > 12 {
        month -= 12;
        year += 1;
    }
    while month < 1 {
        month += 12;
        year -= 1;
    }
    let m = month as u32;
    let d = date.day().min(days_in_month(year, m));
    NaiveDate::from_ymd_opt(year, m, d).unwrap()
}

fn add_years(date: NaiveDate, years: i32) -> NaiveDate {
    let year = date.year() + years;
    let month = date.month();
    let d = date.day().min(days_in_month(year, month));
    NaiveDate::from_ymd_opt(year, month, d).unwrap()
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if SmartDateParser::is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

fn resolve_calendar_date(year: i32, month: u32, day: u32, note: &mut Option<String>) -> NaiveDate {
    let max_d = days_in_month(year, month);
    let mut target_d = day.min(max_d);

    if month == 2 && day >= 29 {
        if !SmartDateParser::is_leap_year(year) {
            target_d = 28;
            *note = Some("Note: Event is on Feb 29th (reminded on Feb 28th in non-leap years)".to_string());
        } else {
            target_d = 29;
            *note = Some("Note: Event is on Feb 29th".to_string());
        }
    }

    NaiveDate::from_ymd_opt(year, month, target_d).unwrap_or_else(|| NaiveDate::from_ymd_opt(year, month, 28).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_time() -> NaiveDateTime {
        // Mock base: Monday, Oct 5, 2026, 10:00:00 AM
        NaiveDate::from_ymd_opt(2026, 10, 5)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
    }

    #[test]
    fn test_prefix_stripping_and_relative_day() {
        let res = SmartDateParser::parse_with_base("Remind me to buy groceries tomorrow", base_time());
        assert_eq!(res.clean_text, "buy groceries");
        assert!(res.timestamp.is_some());
    }

    #[test]
    fn test_time_and_recurrence_extraction() {
        let res = SmartDateParser::parse_with_base("Schedule standup every monday at 9:30 am", base_time());
        assert_eq!(res.clean_text, "standup");
        assert_eq!(res.recurrence, RecurrencePattern::Weekly);
        assert!(res.has_time);
    }

    #[test]
    fn test_tags_and_priority_extraction() {
        let res = SmartDateParser::parse_with_base("Review quarterly budget #finance #work !urgent", base_time());
        assert_eq!(res.clean_text, "Review quarterly budget");
        assert_eq!(res.tags, vec!["finance", "work"]);
        assert_eq!(res.priority, Priority::Urgent);
    }

    #[test]
    fn test_birthday_anniversary_auto_yearly_recurrence() {
        let res = SmartDateParser::parse_with_base("Mom's birthday on Dec 14", base_time());
        assert_eq!(res.recurrence, RecurrencePattern::Yearly);
    }

    #[test]
    fn test_leap_year_handling() {
        // Non-leap year 2027
        let base_2027 = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap().and_hms_opt(10, 0, 0).unwrap();
        let res = SmartDateParser::parse_with_base("Submit taxes on Feb 29", base_2027);
        assert!(res.note.is_some());
        assert!(res.note.unwrap().contains("Feb 28th"));
    }
}
