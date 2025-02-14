#ifndef MS_RTC_RTCP_PACKET_HPP
#define MS_RTC_RTCP_PACKET_HPP

#include "common.hpp"
#include <absl/container/flat_hash_map.h>
#include <string>

namespace RTC
{
	namespace RTCP
	{
		// Internal buffer for RTCP serialization.
		constexpr size_t BufferSize{ 65536 };
		extern uint8_t Buffer[BufferSize];

		// Maximum interval for regular RTCP mode.
		constexpr uint16_t MaxAudioIntervalMs{ 5000 };
		constexpr uint16_t MaxVideoIntervalMs{ 1000 };

		enum class Type : uint8_t
		{
			/**
			 * 发送端报告，用于发送端向所有接收端报告发送活动的统计数据。
			 */
			SR    = 200,
			/**
			 * 接收端报告，由接收端发送给发送端或其他接收者，用来提供关于接收到的数据包的统计信息。
			 */
			RR    = 201,
			/**
			 * 源描述，包含与RTP流相关的CNAME等额外信息。
			 */
			SDES  = 202,
			/**
			 * 表示某个参与者离开会话。
			 */
			BYE   = 203,
			/**
			 * 应用程序定义的RTCP数据报文，允许应用程序自定义一些额外的信息交换。
			 */
			APP   = 204,
			/**
			 * 传输层反馈消息，通常用于提供关于RTP传输层的信息反馈。
			 */
			RTPFB = 205,
			/**
			 * 负载特定反馈消息，针对具体的媒体编码或应用需求提供的反馈。
			 */
			PSFB  = 206,
			/**
			 * 扩展报告，提供额外的报告块以增强基本的SR和RR功能。
			 */
			XR    = 207
		};

		class Packet
		{
		public:
			/* Struct for RTCP common header. */
			struct CommonHeader
			{
#if defined(MS_LITTLE_ENDIAN)
				uint8_t count : 5;
				uint8_t padding : 1;
				uint8_t version : 2;
#elif defined(MS_BIG_ENDIAN)
				uint8_t version : 2;
				uint8_t padding : 1;
				uint8_t count : 5;
#endif
				uint8_t packetType;
				uint16_t length;
			};

		public:
			static const size_t CommonHeaderSize{ 4 };
			static bool IsRtcp(const uint8_t* data, size_t len)
			{
				auto* header = const_cast<CommonHeader*>(reinterpret_cast<const CommonHeader*>(data));

				// clang-format off
				return (
					(len >= CommonHeaderSize) &&
					// DOC: https://tools.ietf.org/html/draft-ietf-avtcore-rfc5764-mux-fixes
					(data[0] > 127 && data[0] < 192) &&
					// RTP Version must be 2.
					(header->version == 2) &&
					// RTCP packet types defined by IANA:
					// http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-4
					// RFC 5761 (RTCP-mux) states this range for secure RTCP/RTP detection.
					(header->packetType >= 192 && header->packetType <= 223)
				);
				// clang-format on
			}
			static Packet* Parse(const uint8_t* data, size_t len);
			static const std::string& Type2String(Type type);

		private:
			static absl::flat_hash_map<Type, std::string> type2String;

		public:
			explicit Packet(Type type) : type(type)
			{
			}
			explicit Packet(CommonHeader* commonHeader)
			{
				this->type   = RTCP::Type(commonHeader->packetType);
				this->header = commonHeader;
			}
			virtual ~Packet() = default;

			void SetNext(Packet* packet)
			{
				this->next = packet;
			}
			Packet* GetNext() const
			{
				return this->next;
			}
			const uint8_t* GetData() const
			{
				return reinterpret_cast<uint8_t*>(this->header);
			}

		public:
			virtual void Dump() const                 = 0;
			virtual size_t Serialize(uint8_t* buffer) = 0;
			virtual Type GetType() const
			{
				return this->type;
			}
			virtual size_t GetCount() const
			{
				return 0u;
			}
			virtual size_t GetSize() const = 0;

		private:
			Type type;
			Packet* next{ nullptr };
			CommonHeader* header{ nullptr };
		};
	} // namespace RTCP
} // namespace RTC

#endif
