import { values } from "lodash";

// The following colors will be used if you pick "Automatic" color
export const BaseColors = {
  "Stacklet 1": "#70ACC3",
  "Stacklet 2": "#212B36",
  "Stacklet 3": "#38A169",
  "Stacklet 4": "#1177BB",
  "Stacklet 5": "#E53E3E",
  "Stacklet 6": "#F6E05E",
  "Stacklet 7": "#AC9D42",
  "Stacklet 8": "#A02B2B",
  "Stacklet 9": "#27714A",
  "Stacklet 10": "#245F77",
  "Stacklet 11": "#A9A6A3",
  "Stacklet 12": "#6D2E17",
  "Stacklet 13": "#C96F42",
  "Stacklet 14": "#D38964",
};

// Additional colors for the user to choose from
export const AdditionalColors = {
  "Blue": "#356AFF",
  "Red": "#E92828",
  "Green": "#3BD973",
  "Purple": "#604FE9",
  "Cyan": "#50F5ED",
  "Orange": "#FB8D3D",
  "Light Blue": "#799CFF",
  "Lilac": "#B554FF",
  "Light Green": "#8CFFB4",
  "Brown": "#A55F2A",
  "Black": "#000000",
  "Gray": "#494949",
  "Pink": "#FF7DE3",
  "Dark Blue": "#002FB4",
  "Indian Red": "#981717",
  "Green 2": "#17BF51",
  "Green 3": "#049235",
  "Dark Turquoise": "#00B6EB",
  "Dark Violet": "#A58AFF",
  "Pink 2": "#C63FA9",
};

export const ColorPaletteArray = values(BaseColors);

const ColorPalette = {
  ...BaseColors,
  ...AdditionalColors,
};

export default ColorPalette;
