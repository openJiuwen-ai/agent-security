# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""调用方传入正则，对流式文本做部分星号替换。"""

from security_mask.stream_mask import StreamSensitiveMask, mask_complete

__all__ = ["StreamSensitiveMask", "mask_complete"]
