// Constants.
const ONE_MINUTE_IN_SECONDS = 60;
const ONE_HOUR_IN_SECONDS = ONE_MINUTE_IN_SECONDS * 60;
const ONE_DAY_IN_SECONDS = ONE_HOUR_IN_SECONDS * 24;
const ONE_DAY_IN_MILLISECONDS = ONE_DAY_IN_SECONDS * 1000;
// From Instagram tag: `<time class="_1o9PC Nzb55" datetime="2020-07-12T03:04:06.000Z" title="Jul 12, 2020">July 12</time>`.
// Instagram datetime post: 2020-07-12T03:04:06.000Z.
// Time-stamp the "ijab qabul" was done: 39:21/59:54 -- so there is 20 mins and 33 secs to go.
// Add the datetime to GMT+7, 10:04:06.
// Subtract the datetime with 20 mins and 33 secs -- 09:43:33.
const WEDDING_DATE = new Date(2013, 3 /* March */, 2, 12, 1, 1);
// Re-assign functions from JavaScript engine.
const { floor, abs } = Math;

// Export.
module.exports = {
    calculate
};

function calculate(currentDate = new Date()) {
    let years;
    let months;
    let days;
    let hours;
    let minutes;
    let seconds;

    // Get raw time.
    const weddingMilliSeconds = WEDDING_DATE.getTime();
    const currentMilliSeconds = currentDate.getTime();
    const diff = currentMilliSeconds - weddingMilliSeconds;

    // We can cut off years first as the number of days is static, 365 or 366.
    years = currentDate.getFullYear() - WEDDING_DATE.getFullYear();

    // For months and days, however, it's a little bit tricky.
    const weddingMonth = WEDDING_DATE.getMonth();
    const currentMonth = currentDate.getMonth();

    // Don't forget to subtract this if date, hours, minutes, seconds is lesser.
    months = currentMonth - weddingMonth;

    // Days.
    const weddingDateInMonth = WEDDING_DATE.getDate();
    const currentDateInMonth = currentDate.getDate();

    days = currentDateInMonth - weddingDateInMonth;

    // We use this to calculate time.
    const daysRemainder = Math.floor((diff % ONE_DAY_IN_MILLISECONDS) / 1000);

    // Time.
    hours = floor(daysRemainder / ONE_HOUR_IN_SECONDS);
    const hoursRemainder = daysRemainder % ONE_HOUR_IN_SECONDS;

    minutes = floor(hoursRemainder / ONE_MINUTE_IN_SECONDS);
    const minutesRemainder = hoursRemainder % ONE_MINUTE_IN_SECONDS;

    seconds = minutesRemainder % ONE_MINUTE_IN_SECONDS;

    if (currentDateInMonth === weddingDateInMonth) {
        // Check hours.
        const weddingHours = WEDDING_DATE.getHours();
        const currentHours = currentDate.getHours();

        if (currentHours < weddingHours) {
            days -= 1;
        } else if (currentHours === weddingHours) {
            // Check minutes.
            const weddingMinutes = WEDDING_DATE.getMinutes();
            const currentMinutes = currentDate.getMinutes();

            if (currentMinutes < weddingMinutes) {
                days -= 1;
            } else if (currentMinutes === weddingMinutes) {
                // Check seconds.
                if (currentDate.getSeconds() < WEDDING_DATE.getSeconds()) {
                    days -= 1;
                }
            }
        }
    }

    // If any of them is less than 1, set to maximum.
    if (days < 0) {
        days += getNumberOfDaysInMonth(currentDate);
        months -= 1;
    }

    if (months < 0) {
        months = 12 + months;
        years -= 1;
    }

    return { years, months, days, hours, minutes, seconds };
}

function render({ years, months, days, hours, minutes, seconds }) {
    // Fill into the divs.
    const yearsDiv = document.getElementById('years');
    const monthsDiv = document.getElementById('months');
    const daysDiv = document.getElementById('days');
    const hoursDiv = document.getElementById('hours');
    const minutesDiv = document.getElementById('minutes');
    const secondsDiv = document.getElementById('seconds');

    yearsDiv.innerHTML = appendZeros(years);
    monthsDiv.innerHTML = appendZeros(months);
    daysDiv.innerHTML = appendZeros(days);
    hoursDiv.innerHTML = appendZeros(hours);
    minutesDiv.innerHTML = appendZeros(minutes);
    secondsDiv.innerHTML = appendZeros(seconds);
}

// Helper functions.
function getNumberOfDaysInMonth(date) {
    const endOfMonth = new Date(date.getFullYear(), date.getMonth() + 1, 0);

    return endOfMonth.getDate();
}

function appendZeros(number) {
    if (number < 10) {
        return `0${number}`;
    }

    return `${number}`;
}