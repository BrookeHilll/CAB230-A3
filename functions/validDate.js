module.exports = (date) => {
    // Check if the date matches the format "YYYY-MM-DD"
    const regex = /^\d{4}-\d{2}-\d{2}$/;
    if (!regex.test(date)) {
        return false;
    }

    // Create a new Date object using the provided date string
    const parts = date.split('-');
    const year = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10) - 1; // Months are zero-based
    const day = parseInt(parts[2], 10);
    const parsedDate = new Date(year, month, day);

    // Check if the parsed date values match the provided date
    if (
        parsedDate.getFullYear() !== year ||
        parsedDate.getMonth() !== month ||
        parsedDate.getDate() !== day
    ) {
        return false;
    }

    // Check if the parsed date is a valid date
    return !isNaN(parsedDate.getTime());
}