
/** This is a utility function to convert any string to a number */
export function convertStringToNumber(input: string): number {
    return input.split('').map((e) => e.charCodeAt(0)).reduce((a, b) => a + b)
}