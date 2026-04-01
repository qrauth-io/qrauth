import type { Dayjs, OpUnitType } from 'dayjs';

import dayjs from 'dayjs';
import duration from 'dayjs/plugin/duration';
import relativeTime from 'dayjs/plugin/relativeTime';

// ----------------------------------------------------------------------

/**
 * Day.js format reference:
 * https://day.js.org/docs/en/display/format
 */

/**
 * Timezone reference:
 * https://day.js.org/docs/en/timezone/set-default-timezone
 */

/**
 * UTC usage:
 * https://day.js.org/docs/en/plugin/utc
 * Example:
 * import utc from 'dayjs/plugin/utc';
 * dayjs.extend(utc);
 * dayjs().utc().format()
 */

dayjs.extend(duration);
dayjs.extend(relativeTime);

// ----------------------------------------------------------------------

export type DateInput = Dayjs | Date | string | number | null | undefined;

export const FORMAT_PATTERNS = {
  dateTime: 'DD MMM YYYY h:mm a', // 17 Apr 2022 12:00 am
  date: 'DD MMM YYYY', // 17 Apr 2022
  time: 'h:mm a', // 12:00 am
  split: {
    dateTime: 'DD/MM/YYYY h:mm a', // 17/04/2022 12:00 am
    date: 'DD/MM/YYYY', // 17/04/2022
  },
  paramCase: {
    dateTime: 'DD-MM-YYYY h:mm a', // 17-04-2022 12:00 am
    date: 'DD-MM-YYYY', // 17-04-2022
  },
};

const INVALID_DATE = 'Invalid';

// ----------------------------------------------------------------------

export function today(template?: string): string {
  return dayjs(new Date()).startOf('day').format(template);
}

// ----------------------------------------------------------------------

/**
 * Formats a date-time string.
 * @returns Formatted date-time string or 'Invalid'.
 * @example
 * fDateTime('17-04-2022') // '17 Apr 2022 12:00 am'
 */
export function fDateTime(input: DateInput, template = FORMAT_PATTERNS.dateTime): string {
  if (!input) return '';

  const date = dayjs(input);
  if (!date.isValid()) return INVALID_DATE;

  return date.format(template);
}

// ----------------------------------------------------------------------

/**
 * Formats a date string.
 * @returns Formatted date string or 'Invalid'.
 * @example
 * fDate('17-04-2022') // '17 Apr 2022'
 */
export function fDate(input: DateInput, template = FORMAT_PATTERNS.date): string {
  if (!input) return '';

  const date = dayjs(input);
  if (!date.isValid()) return INVALID_DATE;

  return date.format(template);
}

// ----------------------------------------------------------------------

/**
 * Formats a time string.
 * @returns Formatted time string or 'Invalid'.
 * @example
 * fTime('2022-04-17T00:00:00') // '12:00 am'
 */
export function fTime(input: DateInput, template = FORMAT_PATTERNS.time): string {
  if (!input) return '';

  const date = dayjs(input);
  if (!date.isValid()) return INVALID_DATE;

  return date.format(template);
}

// ----------------------------------------------------------------------

/**
 * Converts a date input to timestamp.
 * @returns Timestamp in milliseconds or 'Invalid'.
 * @example
 * fTimestamp('2022-04-17') // 1650153600000
 */
export function fTimestamp(input: DateInput): number | string {
  if (!input) return '';

  const date = dayjs(input);
  if (!date.isValid()) return INVALID_DATE;

  return date.valueOf();
}

// ----------------------------------------------------------------------

/**
 * Returns relative time from now to the input.
 * @returns A relative time string.
 * @example
 * fToNow(dayjs().subtract(2, 'days')) // '2 days'
 */
export function fToNow(input: DateInput): string {
  if (!input) return '';

  const date = dayjs(input);
  if (!date.isValid()) return INVALID_DATE;

  return date.toNow(true);
}

// ----------------------------------------------------------------------

/**
 * Checks if a date is between two dates (inclusive).
 * @returns `true` if input is between start and end.
 * @example
 * fIsBetween('2024-01-02', '2024-01-01', '2024-01-03') // true
 */
export function fIsBetween(input: DateInput, start: DateInput, end: DateInput): boolean {
  if (!input || !start || !end) return false;

  const inputDate = dayjs(input);
  const startDate = dayjs(start);
  const endDate = dayjs(end);

  if (!inputDate.isValid() || !startDate.isValid() || !endDate.isValid()) {
    return false;
  }

  const inputValue = inputDate.valueOf();
  const startValue = startDate.valueOf();
  const endValue = endDate.valueOf();

  return (
    inputValue >= Math.min(startValue, endValue) && inputValue <= Math.max(startValue, endValue)
  );
}

// ----------------------------------------------------------------------

/**
 * Checks if one date is after another.
 * @returns `true` if start is after end.
 * @example
 * fIsAfter('2024-05-01', '2024-04-01') // true
 */
export function fIsAfter(start: DateInput, end: DateInput): boolean {
  if (!start || !end) return false;

  const startDate = dayjs(start);
  const endDate = dayjs(end);

  if (!startDate.isValid() || !endDate.isValid()) {
    return false;
  }

  return startDate.isAfter(endDate);
}

// ----------------------------------------------------------------------

/**
 * Checks if two dates are the same by a given unit.
 * @returns `true` if equal by unit.
 * @example
 * fIsSame('2024-04-01', '2024-05-01', 'year') // true
 * fIsSame('2024-04-01', '2023-05-01', 'year') // false
 */
export function fIsSame(start: DateInput, end: DateInput, unit: OpUnitType = 'year'): boolean {
  if (!start || !end) return false;

  const startDate = dayjs(start);
  const endDate = dayjs(end);

  if (!startDate.isValid() || !endDate.isValid()) {
    return false;
  }

  return startDate.isSame(endDate, unit);
}

// ----------------------------------------------------------------------

/**
 * Formats a compact label for a date range based on similarity.
 * @returns Formatted range label or 'Invalid'.
 * @example
 * fDateRangeShortLabel('2024-04-26', '2024-04-26') // '26 Apr 2024'
 * fDateRangeShortLabel('2024-04-25', '2024-04-26') // '25 - 26 Apr 2024'
 * fDateRangeShortLabel('2024-04-25', '2024-05-26') // '25 Apr - 26 May 2024'
 * fDateRangeShortLabel('2023-12-25', '2024-01-01') // '25 Dec 2023 - 01 Jan 2024'
 */
export function fDateRangeShortLabel(start: DateInput, end: DateInput, initial?: boolean): string {
  if (!start || !end) return '';

  const startDate = dayjs(start);
  const endDate = dayjs(end);

  if (!startDate.isValid() || !endDate.isValid() || startDate.isAfter(endDate)) {
    return INVALID_DATE;
  }

  if (initial) {
    return `${fDate(startDate)} - ${fDate(endDate)}`;
  }

  const isSameDay = startDate.isSame(endDate, 'day');
  const isSameMonth = startDate.isSame(endDate, 'month');
  const isSameYear = startDate.isSame(endDate, 'year');

  if (isSameDay) {
    return fDate(endDate);
  }

  if (isSameMonth) {
    return `${fDate(startDate, 'DD')} - ${fDate(endDate)}`;
  }

  if (isSameYear) {
    return `${fDate(startDate, 'DD MMM')} - ${fDate(endDate)}`;
  }

  return `${fDate(startDate)} - ${fDate(endDate)}`;
}

// ----------------------------------------------------------------------

/**
 * Adds duration to the current time.
 * @returns ISO formatted string with the result.
 * @example
 * fAdd({ days: 3 }) // '2025-08-08T12:34:56+00:00'
 */
export type DurationProps = {
  years?: number;
  months?: number;
  days?: number;
  hours?: number;
  minutes?: number;
  seconds?: number;
  milliseconds?: number;
};

export function fAdd({
  years = 0,
  months = 0,
  days = 0,
  hours = 0,
  minutes = 0,
  seconds = 0,
  milliseconds = 0,
}: DurationProps): string {
  const result = dayjs()
    .add(
      dayjs.duration({
        years,
        months,
        days,
        hours,
        minutes,
        seconds,
        milliseconds,
      })
    )
    .format();

  return result;
}

// ----------------------------------------------------------------------

/**
 * Subtracts duration from the current time.
 * @returns ISO formatted string with the result.
 * @example
 * fSub({ months: 1 }) // '2025-07-05T12:34:56+00:00'
 */
export function fSub({
  years = 0,
  months = 0,
  days = 0,
  hours = 0,
  minutes = 0,
  seconds = 0,
  milliseconds = 0,
}: DurationProps): string {
  const result = dayjs()
    .subtract(
      dayjs.duration({
        years,
        months,
        days,
        hours,
        minutes,
        seconds,
        milliseconds,
      })
    )
    .format();

  return result;
}
