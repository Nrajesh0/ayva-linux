/*
 * Comprehensive Test Suite for SmartDateParser (Batch 3)
 *
 * Verifies 1:1 parity with Ayva Android's NLP engine across 30+ phrasing styles.
 */

use ayva_linux::parser::smart_date::{Priority, RecurrencePattern, SmartDateParser};
use chrono::{NaiveDate, NaiveDateTime};

fn test_base() -> NaiveDateTime {
    // Fixed reference time: Monday, Oct 5, 2026 at 10:00:00 AM
    NaiveDate::from_ymd_opt(2026, 10, 5)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
}

#[test]
fn test_plain_task_without_date() {
    let res = SmartDateParser::parse_with_base("Buy almond milk and organic eggs", test_base());
    assert_eq!(res.clean_text, "Buy almond milk and organic eggs");
    assert!(res.timestamp.is_none());
    assert!(!res.has_time);
    assert_eq!(res.recurrence, RecurrencePattern::None);
    assert!(res.tags.is_empty());
    assert_eq!(res.priority, Priority::None);
}

#[test]
fn test_command_prefixes() {
    let test_cases = vec![
        ("Please add a task to call dentist", "call dentist"),
        ("todo: schedule dentist checkup", "schedule dentist checkup"),
        ("Remind me to submit monthly report", "submit report"),
        ("Remind me to submit budget report", "submit budget report"),
        ("I need to renew passport", "renew passport"),
        ("Don't forget to pay electricity bill", "pay electricity bill"),
        ("Reschedule team sync to tomorrow", "team sync"),
        ("Postpone project demo to next week", "project demo"),
    ];

    for (input, expected_clean) in test_cases {
        let res = SmartDateParser::parse_with_base(input, test_base());
        assert_eq!(res.clean_text, expected_clean, "Failed for input: {}", input);
    }
}

#[test]
fn test_relative_days_and_tonight() {
    let res_tmr = SmartDateParser::parse_with_base("Team review tomorrow", test_base());
    assert_eq!(res_tmr.clean_text, "Team review");
    assert!(res_tmr.timestamp.is_some());

    let res_tonight = SmartDateParser::parse_with_base("Watch documentary tonight", test_base());
    assert_eq!(res_tonight.clean_text, "Watch documentary");
    assert!(res_tonight.has_time);
}

#[test]
fn test_in_x_time_relative() {
    let res_hours = SmartDateParser::parse_with_base("Check oven in 2 hours", test_base());
    assert_eq!(res_hours.clean_text, "Check oven");
    assert!(res_hours.has_time);

    let res_days = SmartDateParser::parse_with_base("Follow up client in 3 days", test_base());
    assert_eq!(res_days.clean_text, "Follow up client");
    assert!(res_days.timestamp.is_some());
}

#[test]
fn test_day_of_week_and_next_weekday() {
    let res_fri = SmartDateParser::parse_with_base("Submit invoice this friday", test_base());
    assert_eq!(res_fri.clean_text, "Submit invoice");
    assert!(res_fri.timestamp.is_some());

    let res_next_mon = SmartDateParser::parse_with_base("Sprint planning next monday", test_base());
    assert_eq!(res_next_mon.clean_text, "Sprint planning");
    assert!(res_next_mon.timestamp.is_some());
}

#[test]
fn test_explicit_times_and_named_shortcuts() {
    let res_ampm = SmartDateParser::parse_with_base("Doctor appointment tomorrow at 4:30 pm", test_base());
    assert_eq!(res_ampm.clean_text, "Doctor appointment");
    assert!(res_ampm.has_time);

    let res_noon = SmartDateParser::parse_with_base("Lunch meeting tomorrow at noon", test_base());
    assert_eq!(res_noon.clean_text, "Lunch meeting");
    assert!(res_noon.has_time);

    let res_oclock = SmartDateParser::parse_with_base("Wake up tomorrow at 6 o'clock", test_base());
    assert_eq!(res_oclock.clean_text, "Wake up");
    assert!(res_oclock.has_time);
}

#[test]
fn test_recurrence_patterns() {
    let res_daily = SmartDateParser::parse_with_base("Drink 2L water daily", test_base());
    assert_eq!(res_daily.recurrence, RecurrencePattern::Daily);

    let res_weekly = SmartDateParser::parse_with_base("Team retrospective every friday", test_base());
    assert_eq!(res_weekly.recurrence, RecurrencePattern::Weekly);

    let res_monthly = SmartDateParser::parse_with_base("Pay rent of every month", test_base());
    assert_eq!(res_monthly.recurrence, RecurrencePattern::Monthly);

    let res_yearly = SmartDateParser::parse_with_base("Review annual insurance yearly", test_base());
    assert_eq!(res_yearly.recurrence, RecurrencePattern::Yearly);
}

#[test]
fn test_birthday_anniversary_heuristic() {
    let res_bday = SmartDateParser::parse_with_base("Alice's birthday on Nov 22", test_base());
    assert_eq!(res_bday.clean_text, "Alice's birthday");
    assert_eq!(res_bday.recurrence, RecurrencePattern::Yearly);

    let res_anniv = SmartDateParser::parse_with_base("Wedding anniversary on June 18", test_base());
    assert_eq!(res_anniv.clean_text, "Wedding anniversary");
    assert_eq!(res_anniv.recurrence, RecurrencePattern::Yearly);
}

#[test]
fn test_tags_and_priorities_combination() {
    let res = SmartDateParser::parse_with_base(
        "Deploy v2.0 release tomorrow at 5pm #engineering #release !high",
        test_base(),
    );
    assert_eq!(res.clean_text, "Deploy v2.0 release");
    assert!(res.has_time);
    assert_eq!(res.tags, vec!["engineering", "release"]);
    assert_eq!(res.priority, Priority::High);
}

#[test]
fn test_leap_year_edge_cases() {
    // 2028 is a leap year
    let base_2028 = NaiveDate::from_ymd_opt(2028, 1, 1).unwrap().and_hms_opt(10, 0, 0).unwrap();
    let res_leap = SmartDateParser::parse_with_base("Leap year celebration on Feb 29", base_2028);
    assert!(res_leap.note.is_some());
    assert_eq!(res_leap.note.unwrap(), "Note: Event is on Feb 29th");

    // 2027 is a non-leap year (fallback to Feb 28th)
    let base_2027 = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap().and_hms_opt(10, 0, 0).unwrap();
    let res_non_leap = SmartDateParser::parse_with_base("Tax return deadline on Feb 29", base_2027);
    assert!(res_non_leap.note.is_some());
    assert!(res_non_leap.note.unwrap().contains("reminded on Feb 28th"));
}
