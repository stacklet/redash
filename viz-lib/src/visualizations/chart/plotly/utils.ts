import { isUndefined } from "lodash";
import moment from "moment";
// @ts-ignore
import Lib from "plotly.js-strict-dist";

export function cleanNumber(value: any) {
  return isUndefined(value) ? value : Lib.cleanNumber(value);
}

export function getSeriesAxis(series: any, options: any) {
  const seriesOptions = options.seriesOptions[series.name] || { type: options.globalSeriesType };
  if (seriesOptions.yAxis === 1 && (!options.series.stacking || seriesOptions.type === "line")) {
    return "y2";
  }
  return "y";
}

export function normalizeValue(value: any, axisType: any, dateTimeFormat = "YYYY-MM-DD HH:mm:ss") {
  if (axisType === "datetime" && moment.utc(value).isValid()) {
    value = moment.utc(value);
  }
  if (moment.isMoment(value)) {
    return value.format(dateTimeFormat);
  }
  return value;
}
